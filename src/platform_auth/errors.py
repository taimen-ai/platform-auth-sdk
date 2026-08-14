"""Единый deny-контракт.

Каждый resource service обязан отвечать на отказ одинаково, иначе клиент по
разнице ответов восстанавливает то, что сервер скрывает: существует ли
credential, отозван ли он, лицензирован ли продукт у соседнего tenant.

Поэтому у ошибки две стороны:

* ``client_payload`` — стабильный код и ничего больше. Все дефекты токена
  схлопываются в один ``invalid_token``;
* ``audit_reason`` — точная причина, которая уходит только в audit.

Отдельно выделены ошибки недоступности (``*_unavailable``): они означают, что
решение принять не удалось. Их нельзя трактовать как allow — enforcement
обязан быть fail closed.
"""

from __future__ import annotations

from typing import Any


class EnforcementError(Exception):
    """База: отказ или невозможность принять решение."""

    code = "denied"
    http_status = 403

    def __init__(self, audit_reason: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(audit_reason)
        self.audit_reason = audit_reason
        self.details = details or {}

    @property
    def retriable(self) -> bool:
        """Отказ по существу не повторяют; недоступность — повторяют."""
        return self.http_status >= 500

    def client_payload(self) -> dict[str, str]:
        """Тело ответа клиенту: только стабильный код, без причины."""
        return {"error": self.code}


class InvalidToken(EnforcementError):
    """Любой дефект предъявленного токена.

    Отсутствие, битая подпись, чужой issuer или audience, истёкший срок,
    отозванный credential и отключённый Principal дают один и тот же ответ.
    Разные коды сделали бы endpoint оракулом.
    """

    code = "invalid_token"
    http_status = 401


class InsufficientScope(EnforcementError):
    """Токен валиден, но его scope ceiling не покрывает операцию."""

    code = "insufficient_scope"
    http_status = 403


class NotEntitled(EnforcementError):
    """Identity подтверждена, но продукт или feature не лицензированы."""

    code = "not_entitled"
    http_status = 403


class PermissionDenied(EnforcementError):
    """Identity и лицензия есть, но domain policy сервиса операцию не даёт."""

    code = "permission_denied"
    http_status = 403


class VerificationUnavailable(EnforcementError):
    """Проверить токен нечем: нет ключей, JWKS недоступен дольше окна."""

    code = "verification_unavailable"
    http_status = 503


class EntitlementUnavailable(EnforcementError):
    """Entitlement-решение получить не удалось, а кэш вышел за bounded window."""

    code = "entitlement_unavailable"
    http_status = 503
