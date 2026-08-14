from __future__ import annotations

import pytest

from platform_auth.jwks import JwksCache
from platform_auth.testing import FrozenClock, SigningKey
from platform_auth.verify import TokenVerifier, VerifierConfig

ISSUER = "https://iam.test"
AUDIENCE = "control-plane"


@pytest.fixture
def signing_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def keys(signing_key: SigningKey, clock: FrozenClock) -> JwksCache:
    cache = JwksCache("https://iam.test/.well-known/jwks.json", clock=clock)
    cache.seed(signing_key.jwks())
    return cache


@pytest.fixture
def verifier(keys: JwksCache) -> TokenVerifier:
    return TokenVerifier(keys, VerifierConfig(issuer=ISSUER, audience=AUDIENCE))
