"""Service identity: кэш токена, обновление и молчание о секрете."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from platform_auth.errors import VerificationUnavailable
from platform_auth.service_identity import ServiceCredentials, ServiceTokenProvider
from platform_auth.testing import FrozenClock

IAM_URL = "https://iam.test"

CREDENTIALS = ServiceCredentials(
    client_id="control-plane",
    client_secret="s3cret-value",
    audience="entitlement-service",
    scopes=("entitlement:check-on-behalf",),
)


def _provider(state: dict[str, Any], clock: FrozenClock) -> ServiceTokenProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] = int(state.get("calls", 0)) + 1
        state["last_request"] = request
        if state.get("fail"):
            raise httpx.ConnectError("iam unreachable", request=request)
        return httpx.Response(200, json=state["response"])

    return ServiceTokenProvider(
        IAM_URL,
        CREDENTIALS,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        clock=clock,
    )


async def test_token_is_cached_until_expiry(clock: FrozenClock) -> None:
    state = {"response": {"accessToken": "token-1", "expiresIn": 300}}
    provider = _provider(state, clock)

    assert await provider() == "token-1"
    clock.advance(100)
    assert await provider() == "token-1"

    assert state["calls"] == 1
    await provider.aclose()


async def test_token_is_refreshed_before_it_expires(clock: FrozenClock) -> None:
    """Обновление с запасом: протухший на границе токен получил бы 401."""
    state = {"response": {"accessToken": "token-1", "expiresIn": 300}}
    provider = _provider(state, clock)
    await provider()

    state["response"] = {"accessToken": "token-2", "expiresIn": 300}
    clock.advance(290)

    assert await provider() == "token-2"
    assert state["calls"] == 2
    await provider.aclose()


async def test_outage_is_unavailable_not_empty_token(clock: FrozenClock) -> None:
    state: dict[str, Any] = {"response": {}, "fail": True}
    provider = _provider(state, clock)

    with pytest.raises(VerificationUnavailable) as exc:
        await provider()
    assert exc.value.code == "verification_unavailable"
    await provider.aclose()


async def test_secret_does_not_leak_into_the_error(clock: FrozenClock) -> None:
    state: dict[str, Any] = {"response": {}, "fail": True}
    provider = _provider(state, clock)

    with pytest.raises(VerificationUnavailable) as exc:
        await provider()

    assert CREDENTIALS.client_secret not in str(exc.value)
    assert CREDENTIALS.client_secret not in exc.value.audit_reason
    await provider.aclose()


async def test_malformed_response_is_rejected(clock: FrozenClock) -> None:
    state: dict[str, Any] = {"response": {"accessToken": "", "expiresIn": 0}}
    provider = _provider(state, clock)

    with pytest.raises(VerificationUnavailable) as exc:
        await provider()
    assert exc.value.audit_reason == "service_token_malformed"
    await provider.aclose()


async def test_forget_forces_new_exchange(clock: FrozenClock) -> None:
    state = {"response": {"accessToken": "token-1", "expiresIn": 300}}
    provider = _provider(state, clock)
    await provider()

    provider.forget()
    await provider()

    assert state["calls"] == 2
    await provider.aclose()
