"""Product-neutral enforcement SDK.

Пакет даёт resource service одинаковый способ ответить на четыре вопроса: кто
пришёл (IAM identity), лицензирован ли продукт (entitlement), может ли этот
principal выполнить действие над ресурсом (policy-service, ADR-0025) и как
записать принятое решение (audit). Пятый вопрос — транзакционные гейты самого
продукта — остаётся за сервисом: доменных permissions здесь нет и быть не
должно.

SDK не читает чужие базы данных и не знает про Workspace, Project, Task или
Memory namespace.
"""

from platform_auth.audit import (
    AuditSink,
    CollectingAuditSink,
    DecisionRecord,
    redact,
)
from platform_auth.authorization import (
    AuthorizationClient,
    AuthorizationPolicy,
    CheckItem,
    ContextualTuple,
    NullAuthorizationClient,
    ObjectPage,
    PolicyDecision,
    ResourceRef,
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
    AuthorizationUnavailable,
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
from platform_auth.service_identity import ServiceCredentials, ServiceTokenProvider
from platform_auth.verify import TokenVerifier, VerifierConfig, parse_bearer

__all__ = [
    "Allowed",
    "AuditSink",
    "AuthorizationClient",
    "AuthorizationPolicy",
    "AuthorizationUnavailable",
    "CachingRevocationDirectory",
    "CheckItem",
    "CollectingAuditSink",
    "ContextualTuple",
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
    "NullAuthorizationClient",
    "NullEntitlementClient",
    "ObjectPage",
    "PermissionDenied",
    "PolicyDecision",
    "PolicyEnforcementPoint",
    "Reservation",
    "ResourceRef",
    "RevocationDirectory",
    "ServiceCredentials",
    "ServiceTokenProvider",
    "StaticKeySet",
    "TokenLifetimeWindow",
    "TokenVerifier",
    "TrustedAuthContext",
    "VerificationUnavailable",
    "VerifierConfig",
    "parse_bearer",
    "redact",
]
