"""Проверка access token, выпущенного IAM.

Проверяется всё, что делает токен применимым именно здесь и именно сейчас:
подпись асимметричным алгоритмом, точный issuer, точный audience, временные
claims и обязательный набор полей.

Три вещи запрещены жёстко:

* симметричные алгоритмы и `none` — иначе публичный ключ из JWKS превращается
  в общий секрет и любой клиент подписывает себе токен сам;
* audience по вхождению в список — resource service принимает ровно свой
  audience, иначе единый bearer возвращается через заднюю дверь;
* «мягкий» разбор при отсутствии claim — недостающий `tenant_id` или `sub`
  закрывает вход, а не подставляет значение по умолчанию.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import jwt
from jwt import PyJWK

from platform_auth.context import TrustedAuthContext
from platform_auth.errors import InvalidToken, VerificationUnavailable

REQUIRED_CLAIMS = ("iss", "sub", "aud", "tenant_id", "iat", "nbf", "exp", "jti")

ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512")


class KeySource(Protocol):
    """Источник публичных ключей: JWKS-кэш или статический ключ."""

    async def key_for(self, kid: str) -> PyJWK: ...


@dataclass(frozen=True)
class VerifierConfig:
    issuer: str
    audience: str
    leeway_seconds: float = 5.0
    algorithms: tuple[str, ...] = ALLOWED_ALGORITHMS
    required_claims: tuple[str, ...] = REQUIRED_CLAIMS
    # Дополнительные claims, обязательные для этого сервиса (например `acr`
    # там, где вход без step-up не принимается вовсе).
    extra_required_claims: tuple[str, ...] = field(default=())


def parse_bearer(authorization: str | None) -> str:
    """Достать токен из заголовка. Пустой результат — уже отказ."""
    if not authorization:
        raise InvalidToken("missing_authorization")
    scheme, _, credentials = authorization.partition(" ")
    if scheme.lower() != "bearer" or not credentials.strip():
        raise InvalidToken("malformed_authorization")
    return credentials.strip()


class TokenVerifier:
    def __init__(self, keys: KeySource, config: VerifierConfig) -> None:
        if not config.issuer or not config.audience:
            raise VerificationUnavailable("verifier_not_configured")
        self._keys = keys
        self._config = config

    @property
    def audience(self) -> str:
        return self._config.audience

    async def verify(
        self,
        token: str,
        *,
        correlation_id: str = "",
        causation_id: str = "",
    ) -> TrustedAuthContext:
        if not token:
            raise InvalidToken("missing_token")

        header = self._header(token)
        algorithm = str(header.get("alg", ""))
        if algorithm not in self._config.algorithms:
            # Сюда попадают и `none`, и HS*: подмена алгоритма отсекается до
            # обращения к ключу.
            raise InvalidToken("unsupported_algorithm", details={"alg": algorithm})

        key = await self._keys.key_for(str(header.get("kid", "")))
        claims = self._decode(token, key)
        self._require_claims(claims)

        return TrustedAuthContext.from_claims(
            claims,
            audience=self._config.audience,
            correlation_id=correlation_id,
            causation_id=causation_id,
        )

    def _header(self, token: str) -> Mapping[str, Any]:
        try:
            return dict(jwt.get_unverified_header(token))
        except jwt.PyJWTError as exc:
            raise InvalidToken("malformed_token") from exc

    def _decode(self, token: str, key: PyJWK) -> dict[str, Any]:
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=list(self._config.algorithms),
                issuer=self._config.issuer,
                audience=self._config.audience,
                leeway=self._config.leeway_seconds,
                options={
                    "require": list(self._config.required_claims),
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_signature": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise InvalidToken("expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise InvalidToken("audience_mismatch") from exc
        except jwt.InvalidIssuerError as exc:
            raise InvalidToken("issuer_mismatch") from exc
        except jwt.PyJWTError as exc:
            raise InvalidToken("invalid_token") from exc
        return dict(claims)

    def _require_claims(self, claims: Mapping[str, Any]) -> None:
        missing = [name for name in self._config.extra_required_claims if not claims.get(name)]
        if missing:
            raise InvalidToken("missing_required_claim", details={"claims": missing})
        audience = claims.get("aud")
        # PyJWT принимает audience и списком. Resource service должен работать
        # с credential ровно одного audience, поэтому список отклоняется.
        if not isinstance(audience, str) or audience != self._config.audience:
            raise InvalidToken("audience_not_exact")
