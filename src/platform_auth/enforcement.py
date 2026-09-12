"""Policy Enforcement Point: один порядок проверок для всех сервисов.

Порядок фиксирован и не настраивается:

1. **identity** — токен проверен IAM-подписью, issuer и audience точные;
2. **revocation** — локальная политика сервиса: credential и Principal живы;
3. **entitlement** — продукт и feature лицензированы для этого tenant;
4. **policy** — организационная авторизация: может ли principal выполнить
   действие над найденным ресурсом. Решает внешний policy-service
   (ADR-0025), стадия включается передачей `resource`;
5. **domain** — транзакционные гейты самого сервиса (claim, lease, fencing,
   автор approval). Их SDK не знает и знать не должен.

Порядок именно такой, потому что каждый следующий шаг дороже предыдущего и
осмыслен только после него: спрашивать лицензию для неподтверждённой identity
незачем, а доменное право — единственное, что нельзя вынести из продукта.

Результат любого исхода попадает в audit одной записью. Отказ и недоступность
различаются в журнале, но клиенту оба уходят стабильным кодом.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from platform_auth.audit import AuditSink, CollectingAuditSink, DecisionRecord
from platform_auth.authorization import (
    AuthorizationClient,
    ContextualTuple,
    NullAuthorizationClient,
    PolicyDecision,
    ResourceRef,
)
from platform_auth.context import TrustedAuthContext
from platform_auth.entitlement import Decision, EntitlementClient, NullEntitlementClient
from platform_auth.errors import AuthorizationUnavailable, EnforcementError, InvalidToken
from platform_auth.revocation import (
    RevocationDirectory,
    TokenLifetimeWindow,
    enforce_revocation,
)
from platform_auth.verify import TokenVerifier, parse_bearer

DomainCheck = Callable[[TrustedAuthContext], Awaitable[None]]


@dataclass(frozen=True)
class Allowed:
    """Положительный результат enforcement."""

    context: TrustedAuthContext
    decision: Decision | None = None
    policy: PolicyDecision | None = None

    @property
    def degraded(self) -> bool:
        return self.decision is not None and self.decision.source == "degraded"


class PolicyEnforcementPoint:
    def __init__(
        self,
        verifier: TokenVerifier,
        *,
        entitlement: EntitlementClient | NullEntitlementClient | None = None,
        authorization: AuthorizationClient | NullAuthorizationClient | None = None,
        revocation: RevocationDirectory | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        self._verifier = verifier
        self._entitlement = entitlement or NullEntitlementClient()
        # Для policy заглушка по умолчанию не подставляется: ресурс без
        # клиента — ошибка конфигурации, а не «проверять нечем, пропускаем».
        self._authorization = authorization
        self._revocation: RevocationDirectory = revocation or TokenLifetimeWindow()
        self._audit = audit or CollectingAuditSink()

    @property
    def audit_sink(self) -> AuditSink:
        return self._audit

    async def enforce_authorization_header(
        self,
        authorization: str | None,
        *,
        action: str,
        feature: str = "",
        required_scopes: tuple[str, ...] = (),
        required_amount: int = 0,
        resource: ResourceRef | None = None,
        contextual: Sequence[ContextualTuple] = (),
        policy_consistency: Literal["default", "strong"] = "default",
        domain_check: DomainCheck | None = None,
        correlation_id: str = "",
        causation_id: str = "",
    ) -> Allowed:
        try:
            token = parse_bearer(authorization)
        except EnforcementError as exc:
            self._deny(None, stage="identity", action=action, error=exc)
            raise
        return await self.enforce(
            token,
            action=action,
            feature=feature,
            required_scopes=required_scopes,
            required_amount=required_amount,
            resource=resource,
            contextual=contextual,
            policy_consistency=policy_consistency,
            domain_check=domain_check,
            correlation_id=correlation_id,
            causation_id=causation_id,
        )

    async def enforce(
        self,
        token: str,
        *,
        action: str,
        feature: str = "",
        required_scopes: tuple[str, ...] = (),
        required_amount: int = 0,
        resource: ResourceRef | None = None,
        contextual: Sequence[ContextualTuple] = (),
        policy_consistency: Literal["default", "strong"] = "default",
        domain_check: DomainCheck | None = None,
        correlation_id: str = "",
        causation_id: str = "",
    ) -> Allowed:
        ctx: TrustedAuthContext | None = None

        # 1. identity
        try:
            ctx = await self._verifier.verify(
                token, correlation_id=correlation_id, causation_id=causation_id
            )
        except EnforcementError as exc:
            self._deny(None, stage="identity", action=action, error=exc)
            raise
        except Exception as exc:  # pragma: no cover - защита от неожиданного
            wrapped = InvalidToken("verification_failed")
            self._deny(None, stage="identity", action=action, error=wrapped)
            raise wrapped from exc

        # Scope ceiling — часть identity: он приходит из credential, а не из
        # доменной политики, и только сужает то, что вообще можно просить.
        try:
            if required_scopes:
                ctx.require_scope(*required_scopes)
        except EnforcementError as exc:
            self._deny(ctx, stage="identity", action=action, error=exc)
            raise

        # 2. revocation
        try:
            enforce_revocation(await self._revocation.check(ctx))
        except EnforcementError as exc:
            self._deny(ctx, stage="revocation", action=action, error=exc)
            raise

        # 3. entitlement
        decision: Decision | None = None
        if feature:
            try:
                decision = await self._entitlement.check(
                    ctx, feature=feature, required_amount=required_amount
                )
                decision.raise_if_denied()
            except EnforcementError as exc:
                self._deny(
                    ctx,
                    stage="entitlement",
                    action=action,
                    error=exc,
                    feature=feature,
                    entitlement_source=decision.source if decision else "",
                )
                raise

        # 4. policy — организационная авторизация над найденным ресурсом
        policy: PolicyDecision | None = None
        if resource is not None:
            try:
                if self._authorization is None:
                    # Ресурс передан, а спросить некого. Fail closed: молча
                    # пропустить значило бы включить allow отсутствием строки
                    # в конфигурации.
                    raise AuthorizationUnavailable(
                        "authorization_not_configured",
                        details={"action": action, "resource": resource.key},
                    )
                policy = await self._authorization.check(
                    ctx,
                    action,
                    resource,
                    contextual=contextual,
                    consistency=policy_consistency,
                )
                policy.raise_if_denied()
            except EnforcementError as exc:
                self._deny(
                    ctx,
                    stage="policy",
                    action=action,
                    error=exc,
                    feature=feature,
                    entitlement_source=decision.source if decision else "",
                    policy_source=policy.source if policy else "",
                )
                raise

        # 5. domain — транзакционные гейты сервиса
        if domain_check is not None:
            try:
                await domain_check(ctx)
            except EnforcementError as exc:
                self._deny(
                    ctx,
                    stage="domain",
                    action=action,
                    error=exc,
                    feature=feature,
                    entitlement_source=decision.source if decision else "",
                    policy_source=policy.source if policy else "",
                )
                raise

        if domain_check is not None:
            stage = "domain"
        elif resource is not None:
            stage = "policy"
        else:
            stage = "entitlement"
        self._audit.record(
            DecisionRecord.from_context(
                ctx,
                outcome="allowed",
                stage=stage,
                action=action,
                audience=self._verifier.audience,
                feature=feature,
                product=decision.product if decision else "",
                entitlement_source=decision.source if decision else "",
                policy_source=policy.source if policy else "",
            )
        )
        return Allowed(context=ctx, decision=decision, policy=policy)

    def _deny(
        self,
        ctx: TrustedAuthContext | None,
        *,
        stage: str,
        action: str,
        error: EnforcementError,
        feature: str = "",
        entitlement_source: str = "",
        policy_source: str = "",
    ) -> None:
        self._audit.record(
            DecisionRecord.from_context(
                ctx,
                outcome="unavailable" if error.retriable else "denied",
                stage=stage,
                action=action,
                audience=self._verifier.audience,
                code=error.code,
                reason=error.audit_reason,
                feature=feature,
                entitlement_source=entitlement_source,
                policy_source=policy_source,
                details=error.details,
            )
        )
