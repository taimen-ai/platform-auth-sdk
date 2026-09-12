"""Локальная revocation policy: кэш, устаревание и fail closed."""

from __future__ import annotations

from typing import Any

import pytest

from platform_auth.context import TrustedAuthContext
from platform_auth.errors import InvalidToken, VerificationUnavailable
from platform_auth.revocation import (
    CachingRevocationDirectory,
    CredentialStatus,
    TokenLifetimeWindow,
    enforce_revocation,
)
from platform_auth.testing import FrozenClock, SigningKey
from platform_auth.verify import TokenVerifier


async def _context(
    verifier: TokenVerifier, signing_key: SigningKey, **kwargs: Any
) -> TrustedAuthContext:
    return await verifier.verify(signing_key.issue(**kwargs))


def test_revoked_credential_answers_like_a_broken_token() -> None:
    with pytest.raises(InvalidToken) as exc:
        enforce_revocation(CredentialStatus.revoked("principal_disabled"))

    assert exc.value.code == "invalid_token"
    assert exc.value.audit_reason == "credential_revoked"


async def test_cached_answer_is_reused_inside_ttl(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    calls = {"n": 0}

    async def source(_: TrustedAuthContext) -> CredentialStatus:
        calls["n"] += 1
        return CredentialStatus.allowed()

    directory = CachingRevocationDirectory(source, ttl_seconds=30, clock=clock)
    ctx = await _context(verifier, signing_key)

    await directory.check(ctx)
    clock.advance(10)
    await directory.check(ctx)

    assert calls["n"] == 1


async def test_source_outage_inside_window_keeps_working(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"fail": False}

    async def source(_: TrustedAuthContext) -> CredentialStatus:
        if state["fail"]:
            raise RuntimeError("projection unavailable")
        return CredentialStatus.allowed()

    directory = CachingRevocationDirectory(
        source, ttl_seconds=30, stale_after_seconds=300, clock=clock
    )
    ctx = await _context(verifier, signing_key)
    await directory.check(ctx)

    state["fail"] = True
    clock.advance(60)

    assert (await directory.check(ctx)).active


async def test_source_outage_beyond_window_fails_closed(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    state = {"fail": False}

    async def source(_: TrustedAuthContext) -> CredentialStatus:
        if state["fail"]:
            raise RuntimeError("projection unavailable")
        return CredentialStatus.allowed()

    directory = CachingRevocationDirectory(
        source, ttl_seconds=30, stale_after_seconds=120, clock=clock
    )
    ctx = await _context(verifier, signing_key)
    await directory.check(ctx)

    state["fail"] = True
    clock.advance(300)

    with pytest.raises(VerificationUnavailable) as exc:
        await directory.check(ctx)
    assert exc.value.code == "verification_unavailable"


async def test_revocation_is_not_forgotten_by_ttl(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    """Внутри stale window отказ не переспрашивается, даже когда TTL давно вышел."""
    answers = [CredentialStatus.revoked("revoked"), CredentialStatus.allowed()]

    async def source(_: TrustedAuthContext) -> CredentialStatus:
        return answers.pop(0)

    directory = CachingRevocationDirectory(
        source, ttl_seconds=1, stale_after_seconds=600, clock=clock
    )
    ctx = await _context(verifier, signing_key)

    assert not (await directory.check(ctx)).active
    clock.advance(599)
    assert not (await directory.check(ctx)).active
    assert len(answers) == 1


async def test_negative_answer_is_reasked_after_stale_window(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    """Отказ, полученный до появления записи в directory, не залипает навсегда.

    Control Plane отвечает `binding_not_found`, пока строки binding нет; после
    её появления вход должен открыться без перезапуска процесса.
    """
    answers = [CredentialStatus.revoked("binding_not_found"), CredentialStatus.allowed()]

    async def source(_: TrustedAuthContext) -> CredentialStatus:
        return answers.pop(0)

    directory = CachingRevocationDirectory(
        source, ttl_seconds=30, stale_after_seconds=120, clock=clock
    )
    ctx = await _context(verifier, signing_key)

    assert not (await directory.check(ctx)).active
    clock.advance(121)
    assert (await directory.check(ctx)).active
    assert not answers


async def test_negative_answer_survives_source_outage_after_stale_window(
    verifier: TokenVerifier, signing_key: SigningKey, clock: FrozenClock
) -> None:
    """Повторный опрос не удался — прежний отказ остаётся, а не превращается в allow."""
    calls = 0

    async def source(_: TrustedAuthContext) -> CredentialStatus:
        nonlocal calls
        calls += 1
        if calls == 1:
            return CredentialStatus.revoked("revoked")
        raise RuntimeError("directory down")

    directory = CachingRevocationDirectory(
        source, ttl_seconds=30, stale_after_seconds=120, clock=clock
    )
    ctx = await _context(verifier, signing_key)

    assert not (await directory.check(ctx)).active
    clock.advance(121)
    with pytest.raises(VerificationUnavailable):
        await directory.check(ctx)
    assert calls == 2


async def test_token_lifetime_window_rejects_long_lived_token(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    """Режим «без источника» допустим только для очень коротких токенов."""
    window = TokenLifetimeWindow(max_ttl_seconds=300)

    long_lived = await _context(verifier, signing_key, ttl_seconds=3600)
    assert not (await window.check(long_lived)).active

    short_lived = await _context(verifier, signing_key, ttl_seconds=120)
    assert (await window.check(short_lived)).active
