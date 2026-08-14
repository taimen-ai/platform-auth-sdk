"""Entitlement: кэш, bounded degraded mode и двухфазная квота."""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest

from platform_auth.context import TrustedAuthContext
from platform_auth.entitlement import EntitlementClient, EntitlementPolicy
from platform_auth.errors import EntitlementUnavailable, NotEntitled
from platform_auth.testing import FrozenClock, SigningKey
from platform_auth.verify import TokenVerifier

BASE_URL = "https://entitlement.test"


def _decision_body(*, allowed: bool = True, reason: str = "", **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "decisionId": str(uuid.uuid4()),
        "tenantId": str(uuid.uuid4()),
        "subjectId": str(uuid.uuid4()),
        "product": "control-plane",
        "feature": "tasks",
        "allowed": allowed,
        "reason": reason or ("allowed" if allowed else "no_active_grant"),
        "limits": {},
        "usageSnapshotVersion": 1,
        "policyVersion": 1,
        "validFrom": None,
        "validUntil": None,
    }
    body.update(extra)
    return body


def _client(state: dict[str, Any], clock: FrozenClock, **policy: Any) -> EntitlementClient:
    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] = int(state.get("calls", 0)) + 1
        state["last_request"] = request
        if state.get("fail"):
            raise httpx.ConnectError("entitlement unreachable", request=request)
        status, body = state["response"]
        return httpx.Response(status, json=body)

    async def token_provider() -> str:
        return "service-token"

    return EntitlementClient(
        BASE_URL,
        token_provider,
        product="control-plane",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        policy=EntitlementPolicy(**policy),
        clock=clock,
    )


async def _ctx(verifier: TokenVerifier, signing_key: SigningKey) -> TrustedAuthContext:
    return await verifier.verify(signing_key.issue(), correlation_id="corr-7")


async def test_valid_identity_without_license_is_denied(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body(allowed=False, reason="no_active_grant"))}
    client = _client(state, clock)
    ctx = await _ctx(verifier, signing_key)

    decision = await client.check(ctx, feature="tasks")

    assert not decision.allowed
    with pytest.raises(NotEntitled) as exc:
        decision.raise_if_denied()
    assert exc.value.code == "not_entitled"
    await client.aclose()


async def test_subject_and_correlation_are_taken_from_context(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock)
    ctx = await _ctx(verifier, signing_key)

    await client.check(ctx, feature="tasks")

    request: httpx.Request = state["last_request"]
    assert request.headers["X-Correlation-Id"] == "corr-7"
    assert str(ctx.principal_id).encode() in request.content
    await client.aclose()


async def test_decision_is_cached(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=30)
    ctx = await _ctx(verifier, signing_key)

    await client.check(ctx, feature="tasks")
    clock.advance(10)
    await client.check(ctx, feature="tasks")

    assert state["calls"] == 1
    await client.aclose()


async def test_outage_inside_window_reuses_decision(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=30, degraded_max_age_seconds=300)
    ctx = await _ctx(verifier, signing_key)
    await client.check(ctx, feature="tasks")

    state["fail"] = True
    clock.advance(60)
    decision = await client.check(ctx, feature="tasks")

    assert decision.allowed
    assert decision.source == "degraded"
    await client.aclose()


async def test_outage_beyond_window_fails_closed(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=30, degraded_max_age_seconds=120)
    ctx = await _ctx(verifier, signing_key)
    await client.check(ctx, feature="tasks")

    state["fail"] = True
    clock.advance(300)

    with pytest.raises(EntitlementUnavailable) as exc:
        await client.check(ctx, feature="tasks")
    assert exc.value.code == "entitlement_unavailable"
    assert exc.value.retriable
    await client.aclose()


async def test_degraded_decision_does_not_widen(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    """Кэш на 1 единицу нельзя применить к запросу на 100."""
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=30, degraded_max_age_seconds=300)
    ctx = await _ctx(verifier, signing_key)
    await client.check(ctx, feature="tasks", required_amount=1)

    state["fail"] = True
    clock.advance(60)

    with pytest.raises(EntitlementUnavailable):
        await client.check(ctx, feature="tasks", required_amount=100)
    await client.aclose()


async def test_expired_decision_is_not_reused(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    valid_until = clock().replace(microsecond=0)
    state = {"response": (200, _decision_body(validUntil=valid_until.isoformat()))}
    client = _client(state, clock, cache_ttl_seconds=300, degraded_max_age_seconds=600)
    ctx = await _ctx(verifier, signing_key)
    await client.check(ctx, feature="tasks")

    state["fail"] = True
    clock.advance(60)

    with pytest.raises(EntitlementUnavailable):
        await client.check(ctx, feature="tasks")
    await client.aclose()


async def test_exhausted_quota_denies_reservation(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (409, {"detail": "quota_exhausted"})}
    client = _client(state, clock)
    ctx = await _ctx(verifier, signing_key)

    with pytest.raises(NotEntitled) as exc:
        await client.reserve(ctx, feature="tasks", amount=1, idempotency_key="idem-1")
    assert exc.value.audit_reason == "quota_exhausted"
    await client.aclose()


async def test_reserve_then_consume(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    reservation_id = uuid.uuid4()
    body = {
        "id": str(reservation_id),
        "tenantId": str(uuid.uuid4()),
        "status": "reserved",
        "amount": 1,
        "expiresAt": clock().isoformat(),
        "usageSnapshotVersion": 1,
        "remaining": 9,
    }
    state = {"response": (201, body)}
    client = _client(state, clock)
    ctx = await _ctx(verifier, signing_key)

    reservation = await client.reserve(ctx, feature="tasks", amount=1, idempotency_key="idem-1")
    assert reservation.id == reservation_id

    state["response"] = (200, {**body, "status": "consumed"})
    consumed = await client.consume(ctx, reservation.id)
    assert consumed.status == "consumed"
    await client.aclose()


async def test_reserve_outage_is_not_silently_skipped(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (201, {}), "fail": True}
    client = _client(state, clock)
    ctx = await _ctx(verifier, signing_key)

    with pytest.raises(EntitlementUnavailable):
        await client.reserve(ctx, feature="tasks", amount=1, idempotency_key="idem-1")
    await client.aclose()
