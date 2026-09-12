"""PEP: порядок проверок, fail closed и запись решения в audit."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import pytest

from platform_auth.audit import CollectingAuditSink
from platform_auth.authorization import ContextualTuple, PolicyDecision, ResourceRef
from platform_auth.context import TrustedAuthContext
from platform_auth.enforcement import PolicyEnforcementPoint
from platform_auth.entitlement import Decision
from platform_auth.errors import (
    AuthorizationUnavailable,
    EntitlementUnavailable,
    InsufficientScope,
    InvalidToken,
    NotEntitled,
    PermissionDenied,
)
from platform_auth.revocation import CredentialStatus
from platform_auth.testing import SigningKey
from platform_auth.verify import TokenVerifier


class FakeEntitlement:
    def __init__(self, decision: Decision | Exception) -> None:
        self._decision = decision
        self.calls = 0

    async def check(
        self, ctx: TrustedAuthContext, *, feature: str, required_amount: int = 0
    ) -> Decision:
        self.calls += 1
        if isinstance(self._decision, Exception):
            raise self._decision
        return self._decision


class FakeAuthorization:
    def __init__(self, decision: PolicyDecision | Exception) -> None:
        self._decision = decision
        self.calls: list[dict[str, object]] = []

    async def check(
        self,
        ctx: TrustedAuthContext,
        action: str,
        resource: ResourceRef,
        *,
        contextual: Sequence[ContextualTuple] = (),
        on_behalf_of: str | None = None,
        consistency: str = "default",
    ) -> PolicyDecision:
        self.calls.append(
            {
                "action": action,
                "resource": resource.key,
                "contextual": tuple(contextual),
                "consistency": consistency,
            }
        )
        if isinstance(self._decision, Exception):
            raise self._decision
        return self._decision


class FakeRevocation:
    def __init__(self, status: CredentialStatus) -> None:
        self._status = status
        self.calls = 0

    async def check(self, ctx: TrustedAuthContext) -> CredentialStatus:
        self.calls += 1
        return self._status


def _allowed(feature: str = "tasks") -> Decision:
    return Decision(
        allowed=True, reason="allowed", product="control-plane", feature=feature, source="online"
    )


def _denied(feature: str = "tasks") -> Decision:
    return Decision(
        allowed=False,
        reason="no_active_grant",
        product="control-plane",
        feature=feature,
        source="online",
    )


def _policy(allowed: bool, source: str = "online") -> PolicyDecision:
    return PolicyDecision(
        allowed=allowed,
        reason_code="allowed_by_binding" if allowed else "denied_no_binding",
        decision_id="d-1",
        policy_version="7",
        model_version="m-3",
        source=source,  # type: ignore[arg-type]
        action="tasks.update",
        resource="task:t-1",
    )


def _pep(
    verifier: TokenVerifier,
    *,
    entitlement: object | None = None,
    authorization: object | None = None,
    revocation: object | None = None,
) -> tuple[PolicyEnforcementPoint, CollectingAuditSink]:
    sink = CollectingAuditSink()
    pep = PolicyEnforcementPoint(
        verifier,
        entitlement=entitlement,  # type: ignore[arg-type]
        authorization=authorization,  # type: ignore[arg-type]
        revocation=revocation or FakeRevocation(CredentialStatus.allowed()),  # type: ignore[arg-type]
        audit=sink,
    )
    return pep, sink


async def test_full_chain_allows_and_records_decision(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    pep, sink = _pep(verifier, entitlement=FakeEntitlement(_allowed()))
    domain_calls: list[uuid.UUID] = []

    async def domain_check(ctx: TrustedAuthContext) -> None:
        domain_calls.append(ctx.principal_id)

    result = await pep.enforce_authorization_header(
        f"Bearer {signing_key.issue(scopes=['read'])}",
        action="tasks.list",
        feature="tasks",
        required_scopes=("read",),
        domain_check=domain_check,
    )

    assert result.context.principal_id == domain_calls[0]
    assert not result.degraded
    record = sink.records[-1]
    assert record.outcome == "allowed"
    assert record.action == "tasks.list"
    assert record.audience == "control-plane"


async def test_missing_token_denies_before_anything_else(
    verifier: TokenVerifier,
) -> None:
    entitlement = FakeEntitlement(_allowed())
    revocation = FakeRevocation(CredentialStatus.allowed())
    pep, sink = _pep(verifier, entitlement=entitlement, revocation=revocation)

    with pytest.raises(InvalidToken):
        await pep.enforce_authorization_header(None, action="tasks.list", feature="tasks")

    assert entitlement.calls == 0
    assert revocation.calls == 0
    assert sink.records[-1].stage == "identity"


async def test_wrong_audience_never_reaches_entitlement(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    entitlement = FakeEntitlement(_allowed())
    pep, sink = _pep(verifier, entitlement=entitlement)

    with pytest.raises(InvalidToken):
        await pep.enforce(
            signing_key.issue(audience="memory-service"), action="tasks.list", feature="tasks"
        )

    assert entitlement.calls == 0
    assert sink.records[-1].reason == "audience_mismatch"


async def test_insufficient_scope_stops_at_identity(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    entitlement = FakeEntitlement(_allowed())
    pep, sink = _pep(verifier, entitlement=entitlement)

    with pytest.raises(InsufficientScope):
        await pep.enforce(
            signing_key.issue(scopes=["read"]),
            action="tasks.create",
            feature="tasks",
            required_scopes=("write",),
        )

    assert entitlement.calls == 0
    assert sink.records[-1].stage == "identity"
    assert sink.records[-1].code == "insufficient_scope"


async def test_revoked_credential_stops_before_entitlement(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    entitlement = FakeEntitlement(_allowed())
    pep, sink = _pep(
        verifier,
        entitlement=entitlement,
        revocation=FakeRevocation(CredentialStatus.revoked("principal_disabled")),
    )

    with pytest.raises(InvalidToken):
        await pep.enforce(signing_key.issue(), action="tasks.list", feature="tasks")

    assert entitlement.calls == 0
    assert sink.records[-1].stage == "revocation"


async def test_valid_identity_without_license_is_denied(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    pep, sink = _pep(verifier, entitlement=FakeEntitlement(_denied()))
    domain_called = False

    async def domain_check(_: TrustedAuthContext) -> None:
        nonlocal domain_called
        domain_called = True

    with pytest.raises(NotEntitled):
        await pep.enforce(
            signing_key.issue(),
            action="tasks.list",
            feature="tasks",
            domain_check=domain_check,
        )

    assert not domain_called
    assert sink.records[-1].stage == "entitlement"


async def test_license_without_domain_permission_is_denied(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    pep, sink = _pep(verifier, entitlement=FakeEntitlement(_allowed()))

    async def domain_check(_: TrustedAuthContext) -> None:
        raise PermissionDenied("missing_permission", details={"required": ["tasks:write"]})

    with pytest.raises(PermissionDenied):
        await pep.enforce(
            signing_key.issue(),
            action="tasks.create",
            feature="tasks",
            domain_check=domain_check,
        )

    record = sink.records[-1]
    assert record.stage == "domain"
    assert record.outcome == "denied"


async def test_entitlement_outage_is_unavailable_not_allow(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    pep, sink = _pep(
        verifier,
        entitlement=FakeEntitlement(EntitlementUnavailable("entitlement_service_unavailable")),
    )
    domain_called = False

    async def domain_check(_: TrustedAuthContext) -> None:
        nonlocal domain_called
        domain_called = True

    with pytest.raises(EntitlementUnavailable):
        await pep.enforce(
            signing_key.issue(),
            action="tasks.list",
            feature="tasks",
            domain_check=domain_check,
        )

    assert not domain_called
    assert sink.records[-1].outcome == "unavailable"


async def test_degraded_decision_is_visible_in_result_and_audit(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    degraded = Decision(
        allowed=True,
        reason="allowed",
        product="control-plane",
        feature="tasks",
        source="degraded",
    )
    pep, sink = _pep(verifier, entitlement=FakeEntitlement(degraded))

    result = await pep.enforce(signing_key.issue(), action="tasks.list", feature="tasks")

    assert result.degraded
    assert sink.records[-1].entitlement_source == "degraded"


async def test_audit_record_carries_no_secret(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    pep, sink = _pep(verifier, entitlement=FakeEntitlement(_allowed()))
    token = signing_key.issue()

    await pep.enforce(token, action="tasks.list", feature="tasks")

    serialized = str(sink.records[-1].as_dict())
    assert token not in serialized
    assert "secret" not in serialized.lower()


async def test_policy_stage_allows_and_is_visible_in_result_and_audit(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    authorization = FakeAuthorization(_policy(True, source="cached"))
    pep, sink = _pep(verifier, entitlement=FakeEntitlement(_allowed()), authorization=authorization)
    tuples = (ContextualTuple("task:t-1", "scope", "workspace:w-1"),)

    result = await pep.enforce(
        signing_key.issue(),
        action="tasks.update",
        feature="tasks",
        resource=ResourceRef("task", "t-1"),
        contextual=tuples,
        policy_consistency="strong",
    )

    assert result.policy is not None and result.policy.allowed
    assert authorization.calls == [
        {
            "action": "tasks.update",
            "resource": "task:t-1",
            "contextual": tuples,
            "consistency": "strong",
        }
    ]
    record = sink.records[-1]
    assert record.outcome == "allowed"
    assert record.stage == "policy"
    assert record.policy_source == "cached"
    assert record.as_dict()["policySource"] == "cached"


async def test_policy_deny_is_recorded_before_domain_check(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    pep, sink = _pep(
        verifier,
        entitlement=FakeEntitlement(_allowed()),
        authorization=FakeAuthorization(_policy(False)),
    )
    domain_called = False

    async def domain_check(_: TrustedAuthContext) -> None:
        nonlocal domain_called
        domain_called = True

    with pytest.raises(PermissionDenied) as exc:
        await pep.enforce(
            signing_key.issue(),
            action="tasks.update",
            feature="tasks",
            resource=ResourceRef("task", "t-1"),
            domain_check=domain_check,
        )

    assert not domain_called
    assert exc.value.audit_reason == "denied_no_binding"
    record = sink.records[-1]
    assert record.stage == "policy"
    assert record.outcome == "denied"
    assert record.policy_source == "online"
    assert record.details == {"action": "tasks.update", "resource": "task:t-1"}


async def test_policy_outage_is_unavailable_not_allow(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    pep, sink = _pep(
        verifier,
        authorization=FakeAuthorization(AuthorizationUnavailable("policy_service_unavailable")),
    )

    with pytest.raises(AuthorizationUnavailable):
        await pep.enforce(
            signing_key.issue(), action="tasks.update", resource=ResourceRef("task", "t-1")
        )

    assert sink.records[-1].stage == "policy"
    assert sink.records[-1].outcome == "unavailable"


async def test_resource_without_authorization_client_fails_closed(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    """Ресурс передан, клиент policy не настроен — ошибка конфигурации, не allow."""
    pep, sink = _pep(verifier, entitlement=FakeEntitlement(_allowed()))

    with pytest.raises(AuthorizationUnavailable) as exc:
        await pep.enforce(
            signing_key.issue(),
            action="tasks.update",
            feature="tasks",
            resource=ResourceRef("task", "t-1"),
        )

    assert exc.value.audit_reason == "authorization_not_configured"
    assert exc.value.http_status == 503
    assert sink.records[-1].stage == "policy"
    assert sink.records[-1].outcome == "unavailable"


async def test_without_resource_policy_stage_is_skipped(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    authorization = FakeAuthorization(_policy(False))
    pep, sink = _pep(verifier, authorization=authorization)

    result = await pep.enforce(signing_key.issue(), action="tasks.list")

    assert result.policy is None
    assert authorization.calls == []
    assert sink.records[-1].stage == "entitlement"
