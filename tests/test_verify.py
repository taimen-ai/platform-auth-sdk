"""Проверка токена: что принимается и что закрывается."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from platform_auth.errors import InsufficientScope, InvalidToken
from platform_auth.testing import SigningKey
from platform_auth.verify import TokenVerifier, VerifierConfig, parse_bearer

from .conftest import AUDIENCE, ISSUER


async def test_valid_token_becomes_trusted_context(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    tenant = uuid.uuid4()
    principal = uuid.uuid4()
    session = uuid.uuid4()
    token = signing_key.issue(
        tenant_id=tenant,
        subject=principal,
        scopes=["read", "write"],
        session_id=session,
        acr="mfa",
    )

    ctx = await verifier.verify(token, correlation_id="corr-1")

    assert ctx.tenant_id == tenant
    assert ctx.principal_id == principal
    assert ctx.session_id == session
    assert ctx.audience == AUDIENCE
    assert ctx.acr == "mfa"
    assert ctx.correlation_id == "corr-1"
    assert ctx.has_scope("read")


async def test_token_of_another_audience_is_rejected(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    token = signing_key.issue(audience="memory-service")

    with pytest.raises(InvalidToken) as exc:
        await verifier.verify(token)

    assert exc.value.code == "invalid_token"
    assert exc.value.audit_reason == "audience_mismatch"


async def test_audience_list_is_not_accepted(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    """Мульти-audience токен вернул бы единый bearer через заднюю дверь."""
    token = signing_key.issue(extra_claims={"aud": [AUDIENCE, "memory-service"]})

    with pytest.raises(InvalidToken) as exc:
        await verifier.verify(token)

    assert exc.value.audit_reason == "audience_not_exact"


async def test_foreign_issuer_is_rejected(verifier: TokenVerifier, signing_key: SigningKey) -> None:
    token = signing_key.issue(issuer="https://evil.test")

    with pytest.raises(InvalidToken) as exc:
        await verifier.verify(token)

    assert exc.value.audit_reason == "issuer_mismatch"


async def test_expired_token_is_rejected(verifier: TokenVerifier, signing_key: SigningKey) -> None:
    token = signing_key.issue(issued_at=datetime.now(UTC) - timedelta(hours=2), ttl_seconds=60)

    with pytest.raises(InvalidToken) as exc:
        await verifier.verify(token)

    assert exc.value.audit_reason == "expired"


async def test_symmetric_algorithm_is_rejected(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    """Публичный ключ из JWKS не должен работать как общий секрет."""
    token = signing_key.issue(algorithm="HS256")

    with pytest.raises(InvalidToken) as exc:
        await verifier.verify(token)

    assert exc.value.audit_reason == "unsupported_algorithm"


async def test_unsigned_token_is_rejected(verifier: TokenVerifier, signing_key: SigningKey) -> None:
    token = signing_key.issue(algorithm="none")

    with pytest.raises(InvalidToken) as exc:
        await verifier.verify(token)

    assert exc.value.audit_reason == "unsupported_algorithm"


async def test_token_signed_by_another_key_is_rejected(verifier: TokenVerifier) -> None:
    other = SigningKey.generate(key_id="test-key")
    token = other.issue()

    with pytest.raises(InvalidToken) as exc:
        await verifier.verify(token)

    assert exc.value.audit_reason == "invalid_token"


async def test_unknown_key_id_is_rejected(verifier: TokenVerifier, signing_key: SigningKey) -> None:
    token = signing_key.issue(key_id="rotated-away")

    with pytest.raises(InvalidToken) as exc:
        await verifier.verify(token)

    assert exc.value.audit_reason == "unknown_key_id"


async def test_missing_tenant_claim_closes_entry(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    token = signing_key.issue(drop_claims=("tenant_id",))

    with pytest.raises(InvalidToken):
        await verifier.verify(token)


async def test_extra_required_claim_is_enforced(
    keys: object, signing_key: SigningKey
) -> None:
    """Сервис может требовать step-up: без `acr` вход закрыт, а не понижен."""
    verifier = TokenVerifier(
        keys,  # type: ignore[arg-type]
        VerifierConfig(issuer=ISSUER, audience=AUDIENCE, extra_required_claims=("acr",)),
    )

    with pytest.raises(InvalidToken) as exc:
        await verifier.verify(signing_key.issue())
    assert exc.value.audit_reason == "missing_required_claim"

    ctx = await verifier.verify(signing_key.issue(acr="mfa"))
    assert ctx.acr == "mfa"


async def test_scope_ceiling_only_narrows(verifier: TokenVerifier, signing_key: SigningKey) -> None:
    token = signing_key.issue(scopes=["read", "write"], scope_ceiling=["read"])

    ctx = await verifier.verify(token)

    assert ctx.has_scope("read")
    assert not ctx.has_scope("write")
    assert ctx.effective_scopes() == frozenset({"read"})
    with pytest.raises(InsufficientScope):
        ctx.require_scope("write")


async def test_scope_absent_from_token_is_not_granted_by_ceiling(
    verifier: TokenVerifier, signing_key: SigningKey
) -> None:
    """Ceiling — это потолок, а не источник прав."""
    token = signing_key.issue(scopes=["read"], scope_ceiling=["read", "admin"])

    ctx = await verifier.verify(token)

    assert not ctx.has_scope("admin")


def test_parse_bearer_rejects_other_schemes() -> None:
    with pytest.raises(InvalidToken):
        parse_bearer(None)
    with pytest.raises(InvalidToken):
        parse_bearer("Basic abc")
    with pytest.raises(InvalidToken):
        parse_bearer("Bearer ")
    assert parse_bearer("Bearer abc") == "abc"
