"""Product-neutral enforcement SDK.

Пакет даёт resource service одинаковый способ ответить на три вопроса: кто
пришёл (IAM identity), лицензирован ли продукт (entitlement) и как записать
принятое решение (audit). Четвёртый вопрос — что этой identity можно делать в
самом продукте — остаётся за сервисом: доменных permissions здесь нет и быть
не должно.

SDK не читает чужие базы данных и не знает про Workspace, Project, Task или
Memory namespace.
"""

from platform_auth.audit import (
    AuditSink,
    CollectingAuditSink,
    DecisionRecord,
    redact,
)
from platform_auth.context import TrustedAuthContext
from platform_auth.enforcement import Allowed, PolicyEnforcementPoint
from platform_auth.entitlement import (
    Decision,
    EntitlementClient,
    EntitlementPolicy,
    NullEntitlementClient,
    Reservation,
)
from platform_auth.errors import (
    EnforcementError,
    EntitlementUnavailable,
    InsufficientScope,
    InvalidToken,
    NotEntitled,
    PermissionDenied,
    VerificationUnavailable,
)
from platform_auth.jwks import JwksCache, JwksPolicy, StaticKeySet
from platform_auth.revocation import (
    CachingRevocationDirectory,
    CredentialStatus,
    RevocationDirectory,
    TokenLifetimeWindow,
)
from platform_auth.verify import TokenVerifier, VerifierConfig, parse_bearer

__all__ = [
    "Allowed",
    "AuditSink",
    "CachingRevocationDirectory",
    "CollectingAuditSink",
    "CredentialStatus",
    "Decision",
    "DecisionRecord",
    "EnforcementError",
    "EntitlementClient",
    "EntitlementPolicy",
    "EntitlementUnavailable",
    "InsufficientScope",
    "InvalidToken",
    "JwksCache",
    "JwksPolicy",
    "NotEntitled",
    "NullEntitlementClient",
    "PermissionDenied",
    "PolicyEnforcementPoint",
    "Reservation",
    "RevocationDirectory",
    "StaticKeySet",
    "TokenLifetimeWindow",
    "TokenVerifier",
    "TrustedAuthContext",
    "VerificationUnavailable",
    "VerifierConfig",
    "parse_bearer",
    "redact",
]
