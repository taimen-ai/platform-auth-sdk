"""Помощники для тестов потребителя SDK.

Сервису нужно уметь проверять свой PEP без поднятого IAM: генерировать пару
ключей, выпускать токен с нужными claims и подсовывать JWKS. Модуль намеренно
живёт в самом пакете, а не в тестах, — иначе каждый сервис писал бы свой
вариант и они бы разошлись.

Ключи здесь короткие (2048 бит) и создаются на лету: они нужны для тестов и в
рабочем контуре не применяются.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass
class SigningKey:
    """Пара ключей и её JWKS-представление."""

    private_pem: str
    public_pem: str
    key_id: str
    _private: rsa.RSAPrivateKey

    @classmethod
    def generate(cls, key_id: str = "test-key") -> SigningKey:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        public_pem = (
            private.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        return cls(
            private_pem=private_pem, public_pem=public_pem, key_id=key_id, _private=private
        )

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        numbers = self._private.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.key_id,
                    "n": _b64url_uint(numbers.n),
                    "e": _b64url_uint(numbers.e),
                }
            ]
        }

    def issue(
        self,
        *,
        issuer: str = "https://iam.test",
        audience: str = "control-plane",
        tenant_id: uuid.UUID | str | None = None,
        subject: uuid.UUID | str | None = None,
        scopes: list[str] | None = None,
        principal_type: str = "human",
        credential_id: uuid.UUID | str | None = None,
        scope_ceiling: list[str] | None = None,
        session_id: uuid.UUID | str | None = None,
        acr: str = "",
        auth_time: datetime | None = None,
        ttl_seconds: int = 300,
        issued_at: datetime | None = None,
        algorithm: str = "RS256",
        key_id: str | None = None,
        extra_claims: dict[str, Any] | None = None,
        drop_claims: tuple[str, ...] = (),
    ) -> str:
        now = issued_at or datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": issuer,
            "sub": str(subject or uuid.uuid4()),
            "tenant_id": str(tenant_id or uuid.uuid4()),
            "aud": audience,
            "scope": scopes if scopes is not None else ["read"],
            "principal_type": principal_type,
            "credential_id": str(credential_id or uuid.uuid4()),
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(seconds=ttl_seconds),
            "jti": str(uuid.uuid4()),
        }
        if scope_ceiling is not None:
            claims["scope_ceiling"] = scope_ceiling
        if session_id is not None:
            claims["session_id"] = str(session_id)
        if acr:
            claims["acr"] = acr
        if auth_time is not None:
            claims["auth_time"] = auth_time.isoformat()
        if extra_claims:
            claims.update(extra_claims)
        for name in drop_claims:
            claims.pop(name, None)

        # Симметричный ключ и `none` нужны ровно для того, чтобы проверить, что
        # потребитель их отвергает.
        key: Any
        if algorithm.startswith("RS"):
            key = self.private_pem
        elif algorithm == "none":
            key = None
        else:
            key = "symmetric-key-for-algorithm-confusion-tests"
        return jwt.encode(
            claims,
            key,
            algorithm=algorithm,
            headers={"kid": key_id or self.key_id, "typ": "at+jwt"},
        )


class FrozenClock:
    """Управляемое время: окна кэша проверяются без реального ожидания."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now
