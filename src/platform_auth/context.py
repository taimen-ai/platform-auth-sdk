"""Trusted Auth Context — единственный авторитетный источник identity в запросе.

Контекст собирается только из проверенных claims. Tenant, subject или scope,
присланные клиентом в теле, заголовке или query, авторитетными не считаются
никогда: иначе достаточно валидного токена одного tenant, чтобы объявить себя
другим.

Контекст сознательно не содержит продуктовых permissions. IAM выдаёт identity и
ограничители authority (scope ceiling), а не право на доменную операцию —
permissions выводит сам resource service.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from platform_auth.errors import InsufficientScope, InvalidToken


def _as_scopes(raw: object) -> frozenset[str]:
    """`scope` приходит списком или строкой с пробелами — принимаем оба вида."""
    if isinstance(raw, str):
        return frozenset(item for item in raw.split(" ") if item)
    if isinstance(raw, Sequence) and not isinstance(raw, bytes):
        return frozenset(str(item) for item in raw)
    return frozenset()


def _as_uuid(raw: object, *, reason: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(raw))
    except (TypeError, ValueError) as exc:
        raise InvalidToken(reason) from exc


def _as_optional_uuid(raw: object) -> uuid.UUID | None:
    if raw is None:
        return None
    try:
        return uuid.UUID(str(raw))
    except (TypeError, ValueError):
        return None


def _as_datetime(raw: object) -> datetime | None:
    if raw is None:
        return None
    if isinstance(raw, int | float):
        return datetime.fromtimestamp(float(raw), tz=UTC)
    try:
        parsed = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


@dataclass(frozen=True)
class TrustedAuthContext:
    """Проверенная identity одного запроса."""

    tenant_id: uuid.UUID
    principal_id: uuid.UUID
    principal_type: str
    credential_id: str
    audience: str
    issuer: str
    token_id: str
    scopes: frozenset[str]
    expires_at: datetime
    issued_at: datetime | None = None
    # Ceiling предъявленного Platform Access Token: он только сужает authority.
    scope_ceiling: frozenset[str] = frozenset()
    session_id: uuid.UUID | None = None
    auth_time: datetime | None = None
    acr: str = ""
    correlation_id: str = ""
    causation_id: str = ""
    claims: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_claims(
        cls,
        claims: Mapping[str, Any],
        *,
        audience: str,
        correlation_id: str = "",
        causation_id: str = "",
    ) -> TrustedAuthContext:
        expires_at = _as_datetime(claims.get("exp"))
        if expires_at is None:
            raise InvalidToken("missing_exp")
        credential_id = str(claims.get("credential_id") or claims.get("jti") or "")
        if not credential_id:
            raise InvalidToken("missing_credential_id")
        raw_ceiling = claims.get("scope_ceiling")
        return cls(
            tenant_id=_as_uuid(claims.get("tenant_id"), reason="invalid_tenant"),
            principal_id=_as_uuid(claims.get("sub"), reason="invalid_subject"),
            principal_type=str(claims.get("principal_type", "")),
            credential_id=credential_id,
            audience=audience,
            issuer=str(claims.get("iss", "")),
            token_id=str(claims.get("jti", "")),
            scopes=_as_scopes(claims.get("scope")),
            expires_at=expires_at,
            issued_at=_as_datetime(claims.get("iat")),
            scope_ceiling=_as_scopes(raw_ceiling) if raw_ceiling is not None else frozenset(),
            session_id=_as_optional_uuid(claims.get("session_id")),
            auth_time=_as_datetime(claims.get("auth_time")),
            acr=str(claims.get("acr", "")),
            correlation_id=correlation_id,
            causation_id=causation_id,
            claims=dict(claims),
        )

    def has_scope(self, scope: str) -> bool:
        """Scope действует, только если он есть и в token, и в ceiling.

        Ceiling присутствует не всегда (у service account его нет). Когда он
        есть — он ограничивает: scope вне ceiling не действует, даже если
        попал в token.
        """
        if scope not in self.scopes:
            return False
        return not self.scope_ceiling or scope in self.scope_ceiling

    def require_scope(self, *any_of: str) -> None:
        if not any(self.has_scope(scope) for scope in any_of):
            raise InsufficientScope(
                "scope_not_granted",
                details={"required": sorted(any_of)},
            )

    def effective_scopes(self) -> frozenset[str]:
        if not self.scope_ceiling:
            return self.scopes
        return self.scopes & self.scope_ceiling

    def audit_subject(self) -> dict[str, str]:
        """Безопасный для журнала снимок: идентификаторы, но не секрет."""
        return {
            "tenantId": str(self.tenant_id),
            "principalId": str(self.principal_id),
            "principalType": self.principal_type,
            "credentialId": self.credential_id,
            "audience": self.audience,
            "sessionId": str(self.session_id) if self.session_id else "",
        }
