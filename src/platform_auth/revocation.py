"""Локальная revocation policy resource service.

Короткий срок жизни токена ограничивает ущерб, но не отменяет его: между
отзывом credential в IAM и истечением уже выданного access token остаётся
окно. Закрывать это окно обязан сам resource service — IAM в момент запроса
не участвует.

SDK не решает за сервис, откуда брать признак отзыва: у Control Plane это
собственная read-only проекция Principal, у другого сервиса это может быть
подписка на outbox IAM. Поэтому здесь описан порт `RevocationDirectory` и две
реализации общего назначения — кэширующая и «окно жизни токена».

Ключевое свойство любой реализации: неизвестность трактуется как отказ.
Directory, который не смог ответить, не даёт allow.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from platform_auth.context import TrustedAuthContext
from platform_auth.errors import InvalidToken, VerificationUnavailable

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class CredentialStatus:
    """Ответ источника: активен ли credential и его Principal."""

    active: bool
    reason: str = ""

    @classmethod
    def allowed(cls) -> CredentialStatus:
        return cls(active=True)

    @classmethod
    def revoked(cls, reason: str) -> CredentialStatus:
        return cls(active=False, reason=reason)


class RevocationDirectory(Protocol):
    async def check(self, ctx: TrustedAuthContext) -> CredentialStatus: ...


class TokenLifetimeWindow:
    """Отдельного источника нет: гарантия ограничена сроком жизни токена.

    Режим допустим только там, где TTL access token заведомо мал, и это
    осознанно принятое окно, а не забытая проверка. Чтобы такой режим нельзя
    было включить молча, он ограничивает максимальный принимаемый TTL и
    отклоняет токены, живущие дольше.
    """

    def __init__(self, *, max_ttl_seconds: float = 900.0, clock: Clock = _utcnow) -> None:
        self._max_ttl = max_ttl_seconds
        self._clock = clock

    async def check(self, ctx: TrustedAuthContext) -> CredentialStatus:
        remaining = (ctx.expires_at - self._clock()).total_seconds()
        if remaining > self._max_ttl:
            return CredentialStatus.revoked("token_ttl_exceeds_revocation_window")
        return CredentialStatus.allowed()


class CachingRevocationDirectory:
    """Кэш поверх дорогого источника с жёсткой границей устаревания.

    `ttl_seconds` — как долго переиспользуется положительный ответ.
    `stale_after_seconds` — после какого возраста запись не годится вовсе:
    источник обязан ответить заново, а если не может — вход закрывается.

    Отрицательный ответ (отозван) не кэшируется по TTL: он запоминается до
    истечения самого токена, потому что обратно в active credential уже не
    возвращается, а лишний повторный вызов источника здесь не нужен.
    """

    def __init__(
        self,
        source: Callable[[TrustedAuthContext], Awaitable[CredentialStatus]],
        *,
        ttl_seconds: float = 30.0,
        stale_after_seconds: float = 120.0,
        clock: Clock = _utcnow,
    ) -> None:
        self._source = source
        self._ttl = ttl_seconds
        self._stale_after = stale_after_seconds
        self._clock = clock
        self._entries: dict[str, tuple[datetime, CredentialStatus]] = {}

    async def check(self, ctx: TrustedAuthContext) -> CredentialStatus:
        key = f"{ctx.tenant_id}:{ctx.credential_id}"
        now = self._clock()
        cached = self._entries.get(key)
        if cached is not None:
            stored_at, status = cached
            age = (now - stored_at).total_seconds()
            if not status.active:
                return status
            if age <= self._ttl:
                return status
            if age > self._stale_after:
                # Запись просрочена окончательно: если источник не ответит,
                # решение принимать не на чем.
                self._entries.pop(key, None)
                cached = None

        try:
            status = await self._source(ctx)
        except Exception as exc:
            if cached is not None:
                # Внутри stale window допустимо доработать на прошлом ответе.
                return cached[1]
            raise VerificationUnavailable("revocation_source_unavailable") from exc

        self._entries[key] = (now, status)
        return status

    def forget(self, tenant_id: str, credential_id: str) -> None:
        self._entries.pop(f"{tenant_id}:{credential_id}", None)


def enforce_revocation(status: CredentialStatus) -> None:
    """Отозванный credential отвечает тем же `invalid_token`, что и битый.

    Отдельный код превратил бы endpoint в справочник по чужим credential:
    по разнице ответов видно, существовал ли токен вообще.
    """
    if not status.active:
        raise InvalidToken("credential_revoked", details={"reason": status.reason})
