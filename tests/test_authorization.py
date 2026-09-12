"""Policy-service: разбор решения, кэш в пределах TTL, fail closed, заглушка."""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pytest

from platform_auth.authorization import (
    AuthorizationClient,
    AuthorizationPolicy,
    CheckItem,
    ContextualTuple,
    NullAuthorizationClient,
    ResourceRef,
)
from platform_auth.context import TrustedAuthContext
from platform_auth.errors import AuthorizationUnavailable, PermissionDenied
from platform_auth.testing import FrozenClock, SigningKey
from platform_auth.verify import TokenVerifier

BASE_URL = "https://policy.test"
TASK = ResourceRef("task", "t-1")


def _decision_body(*, allowed: bool = True, reason: str = "", **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "allowed": allowed,
        "reasonCode": reason or ("allowed_by_binding" if allowed else "denied_no_binding"),
        "decisionId": str(uuid.uuid4()),
        "policyVersion": "7",
        "modelVersion": "m-3",
        "evaluatedAt": "2026-09-12T10:00:00Z",
        "consistencyToken": "ct-1",
    }
    body.update(extra)
    return body


def _client(state: dict[str, Any], clock: FrozenClock, **policy: Any) -> AuthorizationClient:
    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] = int(state.get("calls", 0)) + 1
        state["last_request"] = request
        state.setdefault("bodies", []).append(json.loads(request.content))
        if state.get("fail"):
            raise httpx.ConnectError("policy unreachable", request=request)
        status, body = state["response"]
        return httpx.Response(status, json=body)

    async def token_provider() -> str:
        return "service-token"

    return AuthorizationClient(
        BASE_URL,
        token_provider,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        policy=AuthorizationPolicy(**policy),
        clock=clock,
    )


async def _ctx(verifier: TokenVerifier, signing_key: SigningKey) -> TrustedAuthContext:
    return await verifier.verify(signing_key.issue(), correlation_id="corr-9")


async def test_check_parses_decision_and_sends_contract_body(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock)
    ctx = await _ctx(verifier, signing_key)
    tuples = (ContextualTuple("task:t-1", "scope", "workspace:w-1"),)

    decision = await client.check(ctx, "tasks.write", TASK, contextual=tuples)

    assert decision.allowed
    assert decision.reason_code == "allowed_by_binding"
    assert decision.policy_version == "7"
    assert decision.model_version == "m-3"
    assert decision.source == "online"
    assert decision.consistency_token == "ct-1"
    assert decision.evaluated_at is not None and decision.evaluated_at.year == 2026
    assert decision.action == "tasks.write"
    assert decision.resource == "task:t-1"

    request: httpx.Request = state["last_request"]
    assert request.url.path == "/api/v1/decisions:check"
    assert request.headers["Authorization"] == "Bearer service-token"
    assert request.headers["X-Correlation-Id"] == "corr-9"
    body = state["bodies"][0]
    assert "principalId" not in body
    assert body["action"] == "tasks.write"
    assert body["resource"] == {"type": "task", "id": "t-1"}
    assert body["consistency"] == "default"
    assert body["context"]["principalType"] == "human"
    assert body["context"]["contextualTuples"] == [
        {"object": "task:t-1", "relation": "scope", "subject": "workspace:w-1"}
    ]
    await client.aclose()


async def test_denied_decision_raises_permission_denied(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body(allowed=False))}
    client = _client(state, clock)
    ctx = await _ctx(verifier, signing_key)

    decision = await client.check(ctx, "tasks.write", TASK)

    with pytest.raises(PermissionDenied) as exc:
        decision.raise_if_denied()
    assert exc.value.code == "permission_denied"
    assert exc.value.audit_reason == "denied_no_binding"
    assert exc.value.details == {"action": "tasks.write", "resource": "task:t-1"}
    await client.aclose()


async def test_decision_is_cached_within_ttl(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=5)
    ctx = await _ctx(verifier, signing_key)

    first = await client.check(ctx, "tasks.read", TASK)
    clock.advance(3)
    second = await client.check(ctx, "tasks.read", TASK)

    assert state["calls"] == 1
    assert first.source == "online"
    assert second.source == "cached"
    assert second.decision_id == first.decision_id
    await client.aclose()


async def test_cache_expires_after_ttl(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=5)
    ctx = await _ctx(verifier, signing_key)

    await client.check(ctx, "tasks.read", TASK)
    clock.advance(6)
    decision = await client.check(ctx, "tasks.read", TASK)

    assert state["calls"] == 2
    assert decision.source == "online"
    await client.aclose()


async def test_cache_key_includes_resource_and_contextual_tuples(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=5)
    ctx = await _ctx(verifier, signing_key)

    await client.check(ctx, "tasks.read", TASK)
    await client.check(ctx, "tasks.read", ResourceRef("task", "t-2"))
    await client.check(
        ctx,
        "tasks.read",
        TASK,
        contextual=(ContextualTuple("task:t-1", "type_role", "principal:p"),),
    )

    assert state["calls"] == 3
    await client.aclose()


async def test_invalidate_drops_tenant_cache(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=30)
    ctx = await _ctx(verifier, signing_key)
    await client.check(ctx, "tasks.read", TASK)

    client.invalidate(str(uuid.uuid4()))  # чужой tenant — кэш остаётся
    await client.check(ctx, "tasks.read", TASK)
    assert state["calls"] == 1

    client.invalidate(str(ctx.tenant_id))
    await client.check(ctx, "tasks.read", TASK)
    assert state["calls"] == 2

    client.invalidate()
    await client.check(ctx, "tasks.read", TASK)
    assert state["calls"] == 3
    await client.aclose()


async def test_rejected_request_is_unavailable_and_ignores_cache(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    """4xx — сервис отклонил запрос; прошлое allow выдавать нельзя."""
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=30)
    ctx = await _ctx(verifier, signing_key)
    await client.check(ctx, "tasks.read", TASK)
    client.invalidate()

    state["response"] = (403, {"detail": "scope_not_allowed"})
    with pytest.raises(AuthorizationUnavailable) as exc:
        await client.check(ctx, "tasks.read", TASK)

    assert exc.value.code == "authorization_unavailable"
    assert exc.value.http_status == 503
    assert exc.value.audit_reason == "policy_request_rejected"
    assert exc.value.details == {"status": 403, "action": "tasks.read"}
    await client.aclose()


async def test_outage_with_fresh_cache_serves_cached_decision(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=5)
    ctx = await _ctx(verifier, signing_key)
    await client.check(ctx, "tasks.read", TASK)

    state["response"] = (503, {"detail": "engine down"})
    clock.advance(4)
    decision = await client.check(ctx, "tasks.read", TASK)

    assert decision.allowed
    assert decision.source == "cached"
    assert state["calls"] == 1
    await client.aclose()


async def test_outage_without_fresh_cache_fails_closed(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=5)
    ctx = await _ctx(verifier, signing_key)
    await client.check(ctx, "tasks.read", TASK)

    # Кэш старше TTL не продлевается ни на секунду — grace-окна нет.
    state["response"] = (503, {"detail": "engine down"})
    clock.advance(6)
    with pytest.raises(AuthorizationUnavailable) as exc:
        await client.check(ctx, "tasks.read", TASK)
    assert exc.value.audit_reason == "policy_service_unavailable"
    assert exc.value.retriable

    # Транспортная ошибка — тот же исход.
    state["fail"] = True
    with pytest.raises(AuthorizationUnavailable):
        await client.check(ctx, "tasks.read", ResourceRef("task", "t-9"))
    await client.aclose()


async def test_strong_consistency_bypasses_cache(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=30)
    ctx = await _ctx(verifier, signing_key)
    await client.check(ctx, "tasks.write", TASK)

    strong = await client.check(ctx, "tasks.write", TASK, consistency="strong")
    assert strong.source == "online"
    assert state["calls"] == 2
    assert state["bodies"][-1]["consistency"] == "strong"

    # При сбое strong не берёт даже свежий кэш.
    state["response"] = (503, {"detail": "engine down"})
    with pytest.raises(AuthorizationUnavailable):
        await client.check(ctx, "tasks.write", TASK, consistency="strong")

    # А default с тем же свежим кэшем — по-прежнему отвечает.
    cached = await client.check(ctx, "tasks.write", TASK)
    assert cached.source == "cached"
    await client.aclose()


async def test_batch_check_returns_decision_per_item(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {
        "response": (
            200,
            [_decision_body(), _decision_body(allowed=False)],
        )
    }
    client = _client(state, clock)
    ctx = await _ctx(verifier, signing_key)
    items = [
        CheckItem("tasks.read", TASK),
        CheckItem("tasks.write", ResourceRef("task", "t-2"), on_behalf_of="p-2"),
    ]

    decisions = await client.batch_check(ctx, items)

    assert [d.allowed for d in decisions] == [True, False]
    assert decisions[1].action == "tasks.write"
    assert decisions[1].resource == "task:t-2"
    request: httpx.Request = state["last_request"]
    assert request.url.path == "/api/v1/decisions:batch-check"
    body = state["bodies"][0]
    assert len(body) == 2
    assert "principalId" not in body[0]
    assert body[1]["principalId"] == "p-2"

    with pytest.raises(ValueError):
        await client.batch_check(ctx, [CheckItem("tasks.read", TASK)] * 101)
    assert await client.batch_check(ctx, []) == []
    await client.aclose()


async def test_batch_check_with_wrong_length_is_unavailable(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, [_decision_body()])}
    client = _client(state, clock)
    ctx = await _ctx(verifier, signing_key)

    with pytest.raises(AuthorizationUnavailable) as exc:
        await client.batch_check(ctx, [CheckItem("a", TASK), CheckItem("b", TASK)])
    assert exc.value.audit_reason == "policy_response_malformed"
    await client.aclose()


async def test_list_objects_follows_cursor(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, {"objects": ["t-1", "t-2"], "cursor": "c-1", "modelVersion": "m-3"})}
    client = _client(state, clock)
    ctx = await _ctx(verifier, signing_key)

    page = await client.list_objects(ctx, "tasks.read", "task", limit=2)
    assert page.objects == ["t-1", "t-2"]
    assert page.cursor == "c-1"
    assert page.model_version == "m-3"
    first_body = state["bodies"][0]
    assert first_body == {
        "action": "tasks.read",
        "resourceType": "task",
        "consistency": "default",
        "limit": 2,
    }

    state["response"] = (200, {"objects": ["t-3"], "cursor": None, "modelVersion": "m-3"})
    last = await client.list_objects(ctx, "tasks.read", "task", limit=2, cursor=page.cursor)
    assert last.objects == ["t-3"]
    assert last.cursor is None
    assert state["bodies"][1]["cursor"] == "c-1"
    assert state["last_request"].url.path == "/api/v1/decisions:list-objects"

    state["response"] = (502, {"detail": "engine down"})
    with pytest.raises(AuthorizationUnavailable):
        await client.list_objects(ctx, "tasks.read", "task")
    await client.aclose()


async def test_list_subjects_returns_principals(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, {"principals": ["p-1", "p-2"], "modelVersion": "m-3"})}
    client = _client(state, clock)
    ctx = await _ctx(verifier, signing_key)

    subjects = await client.list_subjects(ctx, "approvals.decide", ResourceRef("approval", "a-1"))

    assert subjects == ["p-1", "p-2"]
    assert state["last_request"].url.path == "/api/v1/decisions:list-subjects"
    assert state["bodies"][0] == {
        "action": "approvals.decide",
        "resource": {"type": "approval", "id": "a-1"},
    }
    await client.aclose()


async def test_on_behalf_of_sets_principal_id_and_separate_cache(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"response": (200, _decision_body())}
    client = _client(state, clock, cache_ttl_seconds=30)
    ctx = await _ctx(verifier, signing_key)

    await client.check(ctx, "tasks.read", TASK)
    await client.check(ctx, "tasks.read", TASK, on_behalf_of="p-user")
    await client.list_objects(ctx, "tasks.read", "task", on_behalf_of="p-user")

    assert state["calls"] == 3
    assert "principalId" not in state["bodies"][0]
    assert state["bodies"][1]["principalId"] == "p-user"
    assert state["bodies"][2]["principalId"] == "p-user"
    await client.aclose()


async def test_null_client_denies_instead_of_allowing(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    client = NullAuthorizationClient()
    ctx = await _ctx(verifier, signing_key)

    decision = await client.check(ctx, "tasks.read", TASK)
    assert not decision.allowed
    assert decision.reason_code == "policy_disabled"
    assert decision.source == "disabled"
    with pytest.raises(PermissionDenied):
        decision.raise_if_denied()

    batch = await client.batch_check(ctx, [CheckItem("tasks.read", TASK)])
    assert [d.allowed for d in batch] == [False]
    page = await client.list_objects(ctx, "tasks.read", "task")
    assert page.objects == [] and page.cursor is None
    assert await client.list_subjects(ctx, "tasks.read", TASK) == []
