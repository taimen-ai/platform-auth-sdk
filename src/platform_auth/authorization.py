"""Клиент policy-service: организационная авторизация (Policy Decision Point).

ADR-0025 разделил доменную стадию на две: организационную авторизацию («может
ли principal P выполнить действие A над ресурсом R» с учётом дерева воркспейсов,
отношений на ресурсе и делегирования) и транзакционные гейты самого сервиса.
Первую считает внешний policy-service, и этот модуль — его контракт в SDK.
Транзакционные гейты остаются в `domain_check` PEP.

Свойства те же, что у entitlement, но строже:

* **fail closed.** Нет решения сервиса и нет свежего кэша — нет allow. Кэш
  живёт не дольше `cache_ttl_seconds`, grace-расширений на время сбоя нет:
  ADR-0025 п. 11 — «read/list из cache в пределах TTL, затем deny».
* **strong — без кэша.** Мутации и privileged actions проверяются с
  `consistency="strong"`: ответ берётся только у сервиса, сбой — сразу
  `AuthorizationUnavailable`.
* **отказ — не авария.** 4xx означает, что сервис нас услышал и отклонил сам
  запрос (чужой audience, неизвестный action, нет scope on-behalf). Такой ответ
  закрывает операцию без обращения к кэшу.
* **«выключено» — это deny.** `NullAuthorizationClient` отвечает отказом с
  `source="disabled"`, а не allow: отсутствие настройки policy не должно
  открывать доступ.

Principal и tenant берутся из `TrustedAuthContext` (сервер policy-service —
из токена), ресурс — только серверно найденный `type:id`. Вызов от имени
другого principal (`on_behalf_of`) требует у service identity scope
`policy:check-on-behalf`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Literal

import httpx

from platform_auth.context import TrustedAuthContext
from platform_auth.errors import AuthorizationUnavailable, PermissionDenied

Clock = Callable[[], datetime]
TokenProvider = Callable[[], Awaitable[str]]
Consistency = Literal["default", "strong"]
DecisionSource = Literal["online", "cached", "disabled"]

# Столько элементов принимает `decisions:batch-check` (дизайн v0, раздел 7).
BATCH_LIMIT = 100


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class ResourceRef:
    """Ссылка на ресурс — серверно найденный `type:id`.

    Клиентские claims о ресурсе не принимаются: resource server сам находит
    объект в той же транзакции и только потом спрашивает policy-service.
    """

    type: str
    id: str

    @property
    def key(self) -> str:
        return f"{self.type}:{self.id}"


@dataclass(frozen=True)
class ContextualTuple:
    """Отношение, которого ещё нет в проекции policy-service.

    Нужен при создании ресурса (`task:new#scope@workspace:w`) и для отношений,
    которые вычисляет сам сервис в момент проверки (`task#type_role@principal`).
    Действует только в рамках одного `check`.
    """

    object: str
    relation: str
    subject: str

    def as_dict(self) -> dict[str, str]:
        return {"object": self.object, "relation": self.relation, "subject": self.subject}


@dataclass(frozen=True)
class AuthorizationPolicy:
    """Границы кэша и таймаут запроса."""

    cache_ttl_seconds: float = 5.0
    request_timeout_seconds: float = 3.0


@dataclass(frozen=True)
class PolicyDecision:
    """Решение policy-service по одному действию над одним ресурсом."""

    allowed: bool
    reason_code: str
    decision_id: str
    policy_version: str
    model_version: str
    # online — свежий ответ сервиса; cached — переиспользованный кэш в
    # пределах TTL; disabled — policy выключена, решение отрицательное.
    source: DecisionSource
    consistency_token: str | None = None
    evaluated_at: datetime | None = None
    action: str = ""
    resource: str = ""

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise PermissionDenied(
                self.reason_code or "policy_denied",
                details={"action": self.action, "resource": self.resource},
            )


@dataclass(frozen=True)
class CheckItem:
    """Один элемент `batch_check`."""

    action: str
    resource: ResourceRef
    contextual: tuple[ContextualTuple, ...] = ()
    on_behalf_of: str | None = None


@dataclass(frozen=True)
class ObjectPage:
    """Страница ответа `list_objects`: идентификаторы объектов одного типа."""

    objects: list[str] = field(default_factory=list)
    cursor: str | None = None
    model_version: str = ""


CacheKey = tuple[str, str, str, str, tuple[ContextualTuple, ...]]


class AuthorizationClient:
    """HTTP-клиент decision API policy-service.

    `token_provider` возвращает access token **audience policy-service**:
    resource service предъявляет собственную service identity. Principal,
    для которого спрашивают решение, сервер берёт из токена; чтобы спросить
    про другого (конечного пользователя запроса), нужен `on_behalf_of` и scope
    `policy:check-on-behalf` у service identity.

    Кэшируется только `check` с `consistency="default"`. Ключ — tenant,
    principal (с учётом `on_behalf_of`), action, ресурс и contextual tuples:
    одно и то же действие с другим набором отношений — другое решение.
    """

    def __init__(
        self,
        base_url: str,
        token_provider: TokenProvider,
        *,
        client: httpx.AsyncClient | None = None,
        policy: AuthorizationPolicy | None = None,
        clock: Clock = _utcnow,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token_provider = token_provider
        self._policy = policy or AuthorizationPolicy()
        self._clock = clock
        self._client = client
        self._owns_client = client is None
        self._cache: dict[CacheKey, tuple[datetime, PolicyDecision]] = {}

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def invalidate(self, tenant_id: str | None = None) -> None:
        """Сбросить кэш решений — целиком или для одного tenant.

        Точка подключения подписки на события `binding.*` outbox
        policy-service: отзыв binding не должен жить в кэше даже 5 секунд.
        """
        if tenant_id is None:
            self._cache.clear()
            return
        for key in [key for key in self._cache if key[0] == tenant_id]:
            del self._cache[key]

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._policy.request_timeout_seconds)
        return self._client

    async def _headers(self, ctx: TrustedAuthContext) -> dict[str, str]:
        token = await self._token_provider()
        headers = {"Authorization": f"Bearer {token}"}
        if ctx.correlation_id:
            headers["X-Correlation-Id"] = ctx.correlation_id
        return headers

    async def check(
        self,
        ctx: TrustedAuthContext,
        action: str,
        resource: ResourceRef,
        *,
        contextual: Sequence[ContextualTuple] = (),
        on_behalf_of: str | None = None,
        consistency: Consistency = "default",
    ) -> PolicyDecision:
        tuples = tuple(contextual)
        principal = on_behalf_of or str(ctx.principal_id)
        key: CacheKey = (str(ctx.tenant_id), principal, action, resource.key, tuples)
        now = self._clock()

        if consistency == "default":
            cached = self._fresh(key, now=now)
            if cached is not None:
                return cached

        body = self._check_body(
            ctx,
            action=action,
            resource=resource,
            contextual=tuples,
            on_behalf_of=on_behalf_of,
            consistency=consistency,
        )
        try:
            raw = await self._post("decisions:check", ctx, body, action=action)
        except AuthorizationUnavailable as exc:
            if consistency == "strong" or exc.audit_reason != "policy_service_unavailable":
                raise
            # 5xx или транспорт при обычной согласованности: решение в
            # пределах TTL всё ещё действительно. Такая запись могла появиться
            # от параллельного запроса, пока наш был в полёте; дольше TTL кэш
            # не продлевается — grace-окна у policy нет.
            fallback = self._fresh(key, now=self._clock())
            if fallback is None:
                raise
            return fallback

        decision = _decision(raw, action=action, resource=resource)
        if consistency == "default":
            self._cache[key] = (now, decision)
        return decision

    def _fresh(self, key: CacheKey, *, now: datetime) -> PolicyDecision | None:
        cached = self._cache.get(key)
        if cached is None:
            return None
        stored_at, decision = cached
        if (now - stored_at).total_seconds() > self._policy.cache_ttl_seconds:
            return None
        return replace(decision, source="cached")

    async def batch_check(
        self,
        ctx: TrustedAuthContext,
        items: Sequence[CheckItem],
        *,
        consistency: Consistency = "default",
    ) -> list[PolicyDecision]:
        """Проверить до `BATCH_LIMIT` пар действие–ресурс одним запросом.

        Кэш не участвует ни на чтение, ни на запись: batch нужен спискам и
        массовым операциям, где решения всё равно свежие.
        """
        if len(items) > BATCH_LIMIT:
            raise ValueError(f"batch_check accepts at most {BATCH_LIMIT} items")
        if not items:
            return []
        body = [
            self._check_body(
                ctx,
                action=item.action,
                resource=item.resource,
                contextual=item.contextual,
                on_behalf_of=item.on_behalf_of,
                consistency=consistency,
            )
            for item in items
        ]
        raw = await self._post("decisions:batch-check", ctx, body, action="batch_check")
        if not isinstance(raw, list) or len(raw) != len(items):
            raise AuthorizationUnavailable(
                "policy_response_malformed", details={"action": "batch_check"}
            )
        return [
            _decision(entry, action=item.action, resource=item.resource)
            for entry, item in zip(raw, items, strict=True)
        ]

    async def list_objects(
        self,
        ctx: TrustedAuthContext,
        action: str,
        resource_type: str,
        *,
        on_behalf_of: str | None = None,
        consistency: Consistency = "default",
        cursor: str | None = None,
        limit: int = 1000,
    ) -> ObjectPage:
        """Объекты типа `resource_type`, над которыми principal может `action`.

        Ответ — страница: при `cursor` в ответе следующую страницу запрашивают
        тем же вызовом с этим курсором.
        """
        body: dict[str, Any] = {
            "action": action,
            "resourceType": resource_type,
            "consistency": consistency,
            "limit": limit,
        }
        if on_behalf_of is not None:
            body["principalId"] = on_behalf_of
        if cursor is not None:
            body["cursor"] = cursor
        raw = await self._post("decisions:list-objects", ctx, body, action=action)
        if not isinstance(raw, dict):
            raise AuthorizationUnavailable("policy_response_malformed", details={"action": action})
        next_cursor = raw.get("cursor")
        return ObjectPage(
            objects=[str(item) for item in raw.get("objects") or []],
            cursor=str(next_cursor) if next_cursor else None,
            model_version=str(raw.get("modelVersion", "")),
        )

    async def list_subjects(
        self, ctx: TrustedAuthContext, action: str, resource: ResourceRef
    ) -> list[str]:
        """Principals, которым разрешён `action` над ресурсом.

        Нужен маршрутизации Approval и секции Focus: «кто может решить» —
        ответ policy-service, а не эвристика UI.
        """
        body = {"action": action, "resource": {"type": resource.type, "id": resource.id}}
        raw = await self._post("decisions:list-subjects", ctx, body, action=action)
        if not isinstance(raw, dict):
            raise AuthorizationUnavailable("policy_response_malformed", details={"action": action})
        return [str(item) for item in raw.get("principals") or []]

    def _check_body(
        self,
        ctx: TrustedAuthContext,
        *,
        action: str,
        resource: ResourceRef,
        contextual: Sequence[ContextualTuple],
        on_behalf_of: str | None,
        consistency: Consistency,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "action": action,
            "resource": {"type": resource.type, "id": resource.id},
            "context": {
                "principalType": ctx.principal_type,
                "contextualTuples": [item.as_dict() for item in contextual],
            },
            "consistency": consistency,
        }
        # principalId кладём только от имени другого principal: в остальных
        # случаях сервер берёт principal из токена и расхождение невозможно.
        if on_behalf_of is not None:
            body["principalId"] = on_behalf_of
        return body

    async def _post(
        self, operation: str, ctx: TrustedAuthContext, body: Any, *, action: str
    ) -> Any:
        try:
            response = await self._http().post(
                f"{self._base_url}/api/v1/{operation}",
                json=body,
                headers=await self._headers(ctx),
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code < 500:
                # 4xx — ответ про сам запрос, а не авария: неизвестный action,
                # чужой audience, нет scope on-behalf. Кэш здесь не спасает:
                # выдать прошлое allow значило бы обойти явный отказ.
                raise AuthorizationUnavailable(
                    "policy_request_rejected",
                    details={"status": exc.response.status_code, "action": action},
                ) from exc
            raise AuthorizationUnavailable(
                "policy_service_unavailable", details={"action": action}
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise AuthorizationUnavailable(
                "policy_service_unavailable", details={"action": action}
            ) from exc


def _decision(raw: Any, *, action: str, resource: ResourceRef) -> PolicyDecision:
    if not isinstance(raw, dict):
        raise AuthorizationUnavailable(
            "policy_response_malformed", details={"action": action, "resource": resource.key}
        )
    token = raw.get("consistencyToken")
    return PolicyDecision(
        allowed=bool(raw.get("allowed")),
        reason_code=str(raw.get("reasonCode", "")),
        decision_id=str(raw.get("decisionId", "")),
        policy_version=str(raw.get("policyVersion", "")),
        model_version=str(raw.get("modelVersion", "")),
        source="online",
        consistency_token=str(token) if token else None,
        evaluated_at=_parse_time(raw.get("evaluatedAt")),
        action=action,
        resource=resource.key,
    )


def _parse_time(raw: object) -> datetime | None:
    if raw is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


class NullAuthorizationClient:
    """Заглушка для контуров, где policy-service ещё не подключён.

    В отличие от `NullEntitlementClient`, отвечает **deny**, а не allow.
    Лицензия «выключена» означает «продукт не ограничен», а организационная
    авторизация «выключена» означает, что права никто не проверил — и
    превращать это в доступ нельзя. Заглушка нужна, чтобы стадия `policy`
    была включена явно: сервис, передавший `resource`, получает
    воспроизводимый отказ `policy_disabled` с `source="disabled"`, который
    виден в audit, а не тихое разрешение.
    """

    async def check(
        self,
        ctx: TrustedAuthContext,
        action: str,
        resource: ResourceRef,
        *,
        contextual: Sequence[ContextualTuple] = (),
        on_behalf_of: str | None = None,
        consistency: Consistency = "default",
    ) -> PolicyDecision:
        return self._disabled(action=action, resource=resource)

    async def batch_check(
        self,
        ctx: TrustedAuthContext,
        items: Sequence[CheckItem],
        *,
        consistency: Consistency = "default",
    ) -> list[PolicyDecision]:
        return [self._disabled(action=item.action, resource=item.resource) for item in items]

    async def list_objects(
        self,
        ctx: TrustedAuthContext,
        action: str,
        resource_type: str,
        *,
        on_behalf_of: str | None = None,
        consistency: Consistency = "default",
        cursor: str | None = None,
        limit: int = 1000,
    ) -> ObjectPage:
        return ObjectPage()

    async def list_subjects(
        self, ctx: TrustedAuthContext, action: str, resource: ResourceRef
    ) -> list[str]:
        return []

    def invalidate(self, tenant_id: str | None = None) -> None:
        return None

    async def aclose(self) -> None:  # pragma: no cover - симметрия интерфейса
        return None

    @staticmethod
    def _disabled(*, action: str, resource: ResourceRef) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            reason_code="policy_disabled",
            decision_id="",
            policy_version="",
            model_version="",
            source="disabled",
            action=action,
            resource=resource.key,
        )
