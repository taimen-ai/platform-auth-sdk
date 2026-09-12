"""Audit envelope решения авторизации.

Запись об отказе полезна ровно настолько, насколько она безопасна. Поэтому в
конверт попадают идентификаторы и коды, но никогда — сам токен, его hash,
секрет, upstream `subject` или тело запроса.

Точная причина отказа живёт только здесь. Клиенту уходит стабильный код
(см. `errors`), а `reason` остаётся во внутреннем журнале: разделение не даёт
превратить endpoint в оракул и одновременно оставляет возможность разобраться,
почему конкретный запрос был закрыт.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from platform_auth.context import TrustedAuthContext

SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "secret",
        "password",
        "api_key",
        "apikey",
        "key_hash",
        "keyhash",
        "assertion",
        "client_secret",
        "subject",
    }
)

SECRET_PREFIXES = ("iam_pat_", "cp_", "eyJ")


def redact(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Убрать из произвольного словаря всё, что похоже на credential.

    Проверяется и имя поля, и значение: credential, попавший в поле с
    безобидным именем, всё равно не должен уехать в журнал.
    """
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if key.lower().replace("-", "_") in SENSITIVE_KEYS:
            cleaned[key] = "[redacted]"
            continue
        if isinstance(value, Mapping):
            cleaned[key] = redact(value)
            continue
        if isinstance(value, str) and value.startswith(SECRET_PREFIXES):
            cleaned[key] = "[redacted]"
            continue
        cleaned[key] = value
    return cleaned


@dataclass(frozen=True)
class DecisionRecord:
    """Одно решение PEP: что просили, что решили и почему."""

    outcome: str  # allowed | denied | unavailable
    stage: str  # identity | revocation | entitlement | policy | domain
    action: str
    audience: str
    code: str = ""
    reason: str = ""
    tenant_id: str = ""
    principal_id: str = ""
    principal_type: str = ""
    credential_id: str = ""
    session_id: str = ""
    product: str = ""
    feature: str = ""
    entitlement_source: str = ""
    # online | cached | disabled — источник решения policy-service.
    policy_source: str = ""
    correlation_id: str = ""
    causation_id: str = ""
    recorded_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_context(
        cls,
        ctx: TrustedAuthContext | None,
        *,
        outcome: str,
        stage: str,
        action: str,
        audience: str,
        code: str = "",
        reason: str = "",
        product: str = "",
        feature: str = "",
        entitlement_source: str = "",
        policy_source: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> DecisionRecord:
        subject = ctx.audit_subject() if ctx is not None else {}
        return cls(
            outcome=outcome,
            stage=stage,
            action=action,
            audience=audience,
            code=code,
            reason=reason,
            tenant_id=subject.get("tenantId", ""),
            principal_id=subject.get("principalId", ""),
            principal_type=subject.get("principalType", ""),
            credential_id=subject.get("credentialId", ""),
            session_id=subject.get("sessionId", ""),
            product=product,
            feature=feature,
            entitlement_source=entitlement_source,
            policy_source=policy_source,
            correlation_id=ctx.correlation_id if ctx else "",
            causation_id=ctx.causation_id if ctx else "",
            details=redact(details or {}),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "stage": self.stage,
            "action": self.action,
            "audience": self.audience,
            "code": self.code,
            "reason": self.reason,
            "tenantId": self.tenant_id,
            "principalId": self.principal_id,
            "principalType": self.principal_type,
            "credentialId": self.credential_id,
            "sessionId": self.session_id,
            "product": self.product,
            "feature": self.feature,
            "entitlementSource": self.entitlement_source,
            "policySource": self.policy_source,
            "correlationId": self.correlation_id,
            "causationId": self.causation_id,
            "recordedAt": self.recorded_at.isoformat(),
            "details": self.details,
        }


class AuditSink(Protocol):
    """Куда сервис складывает решения. Синхронный вызов — запись дешёвая."""

    def record(self, decision: DecisionRecord) -> None: ...


class CollectingAuditSink:
    """Накопитель в памяти: тесты и дефолт, когда сервис свой sink не дал."""

    def __init__(self, limit: int = 1000) -> None:
        self._limit = limit
        self.records: list[DecisionRecord] = []

    def record(self, decision: DecisionRecord) -> None:
        self.records.append(decision)
        if len(self.records) > self._limit:
            del self.records[: len(self.records) - self._limit]

    def clear(self) -> None:
        self.records.clear()
