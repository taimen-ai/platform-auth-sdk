"""Кэш JWKS: ротация, ограничение частоты обновления и жёсткое устаревание."""

from __future__ import annotations

import httpx
import pytest

from platform_auth.errors import InvalidToken, VerificationUnavailable
from platform_auth.jwks import JwksCache, JwksPolicy
from platform_auth.testing import FrozenClock, SigningKey

JWKS_URL = "https://iam.test/.well-known/jwks.json"


def _transport(state: dict[str, object]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] = int(state.get("calls", 0)) + 1
        if state.get("fail"):
            raise httpx.ConnectError("jwks unreachable", request=request)
        return httpx.Response(200, json=state["document"])

    return httpx.MockTransport(handler)


async def test_rotation_is_picked_up_on_unknown_kid(clock: FrozenClock) -> None:
    first = SigningKey.generate(key_id="key-1")
    second = SigningKey.generate(key_id="key-2")
    state: dict[str, object] = {"document": first.jwks()}
    cache = JwksCache(
        JWKS_URL,
        client=httpx.AsyncClient(transport=_transport(state)),
        clock=clock,
    )

    assert await cache.key_for("key-1") is not None

    # IAM повернул ключ: новый kid ещё не в кэше.
    state["document"] = second.jwks()
    clock.advance(1)
    with pytest.raises(InvalidToken):
        await cache.key_for("key-2")

    # Повторная попытка после min_refresh_interval уже видит новый ключ.
    clock.advance(30)
    assert await cache.key_for("key-2") is not None
    await cache.aclose()


async def test_refresh_is_rate_limited(clock: FrozenClock) -> None:
    """Поток запросов с неизвестным kid не должен превращаться в DDoS по IAM."""
    key = SigningKey.generate(key_id="key-1")
    state: dict[str, object] = {"document": key.jwks()}
    cache = JwksCache(
        JWKS_URL,
        client=httpx.AsyncClient(transport=_transport(state)),
        policy=JwksPolicy(min_refresh_interval_seconds=60),
        clock=clock,
    )

    for _ in range(5):
        with pytest.raises(InvalidToken):
            await cache.key_for("missing")
        clock.advance(1)

    assert state["calls"] == 1
    await cache.aclose()


async def test_cache_survives_short_outage(clock: FrozenClock) -> None:
    key = SigningKey.generate(key_id="key-1")
    state: dict[str, object] = {"document": key.jwks()}
    cache = JwksCache(
        JWKS_URL,
        client=httpx.AsyncClient(transport=_transport(state)),
        policy=JwksPolicy(refresh_after_seconds=60, stale_after_seconds=600),
        clock=clock,
    )
    await cache.key_for("key-1")

    state["fail"] = True
    clock.advance(120)

    # Мягкий срок истёк, жёсткий — нет: сервис продолжает работать.
    assert await cache.key_for("key-1") is not None
    await cache.aclose()


async def test_stale_cache_fails_closed(clock: FrozenClock) -> None:
    """Дольше stale window непроверенный кэш не живёт: отказ, а не доверие."""
    key = SigningKey.generate(key_id="key-1")
    state: dict[str, object] = {"document": key.jwks()}
    cache = JwksCache(
        JWKS_URL,
        client=httpx.AsyncClient(transport=_transport(state)),
        policy=JwksPolicy(
            refresh_after_seconds=60, stale_after_seconds=300, min_refresh_interval_seconds=1
        ),
        clock=clock,
    )
    await cache.key_for("key-1")

    state["fail"] = True
    clock.advance(400)

    with pytest.raises(VerificationUnavailable) as exc:
        await cache.key_for("key-1")
    assert exc.value.code == "verification_unavailable"
    assert exc.value.retriable
    await cache.aclose()


async def test_symmetric_key_in_jwks_is_ignored(clock: FrozenClock) -> None:
    state: dict[str, object] = {
        "document": {"keys": [{"kty": "oct", "kid": "sym", "k": "c2VjcmV0"}]}
    }
    cache = JwksCache(
        JWKS_URL,
        client=httpx.AsyncClient(transport=_transport(state)),
        clock=clock,
    )

    with pytest.raises(VerificationUnavailable):
        await cache.key_for("sym")
    await cache.aclose()
