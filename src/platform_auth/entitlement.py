"""Клиент entitlement-service: decision и quota reservation.

Порядок enforcement фиксирован: identity подтверждена IAM, дальше проверяется
лицензия, и только потом доменная политика продукта. Здесь — средний шаг.

Два свойства важнее удобства:

* **fail closed.** Недоступный entitlement-service не означает allow. Кэш
  разрешает пережить короткий сбой, но только в пределах bounded window и
  только на ранее полученном решении. Просроченный кэш даёт
  `entitlement_unavailable`, а не тихое «разрешено».
* **stale не расширяет.** Устаревшее решение нельзя применить к запросу с
  большим `required_amount`, чем тот, на котором оно было получено: иначе
  кэш превращается в способ обойти квоту во время сбоя.

Квота списывается двухфазно: `reserve` → `consume`. Резерв идемпотентен по
`idempotency_key`, поэтому повтор запроса после неоднозначного ответа не
списывает лимит дважды.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from platform_auth.context import TrustedAuthContext
from platform_auth.errors import EntitlementUnavailable, NotEntitled

Clock = Callable[[], datetime]
TokenProvider = Callable[[], Awaitable[str]]


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class EntitlementPolicy:
    """Границы кэша и деградации."""

    cache_ttl_seconds: float = 30.0
    # Сколько ещё можно работать на кэше, когда сервис недоступен.
    degraded_max_age_seconds: float = 300.0
    request_timeout_seconds: float = 3.0


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    product: str
    feature: str
    decision_id: str = ""
    limits: dict[str, Any] = field(default_factory=dict)
    valid_until: datetime | None = None
    policy_version: int = 0
    # online — свежий ответ сервиса; degraded — переиспользованный кэш.
    source: str = "online"
    required_amount: int = 0

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise NotEntitled(
                self.reason or "not_entitled",
                details={"product": self.product, "feature": self.feature},
            )


@dataclass(frozen=True)
class Reservation:
    id: uuid.UUID
    status: str
    amount: int
    expires_at: datetime
    remaining: int | None = None


class EntitlementClient:
    """HTTP-клиент decision API.

    `token_provider` возвращает access token **audience entitlement-service**:
    resource service предъявляет собственную service identity, а конечного
    пользователя указывает `subjectId`. Для этого его identity нужен scope
    `entitlement:check-on-behalf` — без него сервис может спрашивать только
    про себя.
    """

    def __init__(
        self,
        base_url: str,
        token_provider: TokenProvider,
        *,
        product: str,
        client: httpx.AsyncClient | None = None,
        policy: EntitlementPolicy | None = None,
        clock: Clock = _utcnow,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token_provider = token_provider
        self._product = product
        self._policy = policy or EntitlementPolicy()
        self._clock = clock
        self._client = client
        self._owns_client = client is None
        self._cache: dict[tuple[str, str, str, str], tuple[datetime, Decision]] = {}

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

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
        *,
        feature: str,
        required_amount: int = 0,
    ) -> Decision:
        key = (str(ctx.tenant_id), str(ctx.principal_id), self._product, feature)
        now = self._clock()
        cached = self._cache.get(key)

        if cached is not None:
            stored_at, decision = cached
            age = (now - stored_at).total_seconds()
            fresh = age <= self._policy.cache_ttl_seconds
            not_expired = decision.valid_until is None or decision.valid_until > now
            wide_enough = required_amount <= decision.required_amount
            if fresh and not_expired and wide_enough:
                return decision

        try:
            decision = await self._check_online(
                ctx, feature=feature, required_amount=required_amount
            )
        except (httpx.HTTPError, ValueError) as exc:
            degraded = self._degraded(cached, now=now, required_amount=required_amount)
            if degraded is None:
                raise EntitlementUnavailable(
                    "entitlement_service_unavailable",
                    details={"product": self._product, "feature": feature},
                ) from exc
            return degraded

        self._cache[key] = (now, decision)
        return decision

    def _degraded(
        self,
        cached: tuple[datetime, Decision] | None,
        *,
        now: datetime,
        required_amount: int,
    ) -> Decision | None:
        """Переиспользовать прошлое решение, не расширяя его."""
        if cached is None:
            return None
        stored_at, decision = cached
        if (now - stored_at).total_seconds() > self._policy.degraded_max_age_seconds:
            return None
        if decision.valid_until is not None and decision.valid_until <= now:
            return None
        if required_amount > decision.required_amount:
            return None
        return Decision(
            allowed=decision.allowed,
            reason=decision.reason,
            product=decision.product,
            feature=decision.feature,
            decision_id=decision.decision_id,
            limits=decision.limits,
            valid_until=decision.valid_until,
            policy_version=decision.policy_version,
            source="degraded",
            required_amount=decision.required_amount,
        )

    async def _check_online(
        self, ctx: TrustedAuthContext, *, feature: str, required_amount: int
    ) -> Decision:
        response = await self._http().post(
            f"{self._base_url}/api/v1/decisions:check",
            json={
                "product": self._product,
                "feature": feature,
                "subjectId": str(ctx.principal_id),
                "requiredAmount": required_amount,
                "correlationId": ctx.correlation_id,
            },
            headers=await self._headers(ctx),
        )
        response.raise_for_status()
        body = response.json()
        return Decision(
            allowed=bool(body.get("allowed")),
            reason=str(body.get("reason", "")),
            product=str(body.get("product", self._product)),
            feature=str(body.get("feature", feature)),
            decision_id=str(body.get("decisionId", "")),
            limits=dict(body.get("limits") or {}),
            valid_until=_parse_time(body.get("validUntil")),
            policy_version=int(body.get("policyVersion") or 0),
            source="online",
            required_amount=required_amount,
        )

    async def reserve(
        self,
        ctx: TrustedAuthContext,
        *,
        feature: str,
        amount: int,
        idempotency_key: str,
    ) -> Reservation:
        """Зарезервировать квоту под предстоящую мутацию.

        Отказ сервиса на этом шаге закрывает операцию: резерв — часть
        transactional gate, и «продолжить без резерва» означало бы списать
        лимит задним числом или не списать вовсе.
        """
        try:
            response = await self._http().post(
                f"{self._base_url}/api/v1/quota:reserve",
                json={
                    "product": self._product,
                    "feature": feature,
                    "subjectId": str(ctx.principal_id),
                    "amount": amount,
                    "idempotencyKey": idempotency_key,
                    "correlationId": ctx.correlation_id,
                },
                headers=await self._headers(ctx),
            )
        except httpx.HTTPError as exc:
            raise EntitlementUnavailable("quota_reserve_unavailable") from exc

        if response.status_code == 409:
            raise NotEntitled(
                _detail(response) or "quota_exhausted",
                details={"product": self._product, "feature": feature},
            )
        response.raise_for_status()
        return _reservation(response.json())

    async def consume(self, ctx: TrustedAuthContext, reservation_id: uuid.UUID) -> Reservation:
        return await self._finish(ctx, reservation_id, "consume")

    async def release(self, ctx: TrustedAuthContext, reservation_id: uuid.UUID) -> Reservation:
        return await self._finish(ctx, reservation_id, "release")

    async def _finish(
        self, ctx: TrustedAuthContext, reservation_id: uuid.UUID, action: str
    ) -> Reservation:
        try:
            response = await self._http().post(
                f"{self._base_url}/api/v1/quota/{reservation_id}:{action}",
                headers=await self._headers(ctx),
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise EntitlementUnavailable(f"quota_{action}_unavailable") from exc
        return _reservation(response.json())


def _detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return ""
    detail = body.get("detail") if isinstance(body, dict) else None
    return str(detail) if detail else ""


def _reservation(body: dict[str, Any]) -> Reservation:
    expires_at = _parse_time(body.get("expiresAt"))
    return Reservation(
        id=uuid.UUID(str(body["id"])),
        status=str(body.get("status", "")),
        amount=int(body.get("amount") or 0),
        expires_at=expires_at or _utcnow(),
        remaining=body.get("remaining"),
    )


def _parse_time(raw: object) -> datetime | None:
    if raw is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


class NullEntitlementClient:
    """Заглушка для контуров, где лицензирование ещё не включено.

    Существует, чтобы включение entitlement было явным решением конфигурации,
    а не побочным эффектом отсутствия настройки. Всегда отвечает allow и
    помечает решение источником `disabled` — в audit это видно.
    """

    def __init__(self, product: str = "") -> None:
        self._product = product

    async def check(
        self, ctx: TrustedAuthContext, *, feature: str, required_amount: int = 0
    ) -> Decision:
        return Decision(
            allowed=True,
            reason="entitlement_disabled",
            product=self._product,
            feature=feature,
            source="disabled",
            required_amount=required_amount,
        )

    async def aclose(self) -> None:  # pragma: no cover - симметрия интерфейса
        return None
