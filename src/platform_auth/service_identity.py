"""Собственная service identity resource service.

Чтобы спросить entitlement-service о лицензии пользователя, Control Plane
предъявляет **свой** credential, а не токен этого пользователя: токен выпущен
для audience `control-plane` и в другом сервисе не принимается — это ровно то
свойство, ради которого единый bearer и запрещён.

Провайдер меняет client_id/secret на короткоживущий token нужного audience и
держит его в памяти до истечения. Секрет не пишется в журнал и не попадает в
исключения: наружу уходит только факт неудачи.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx

from platform_auth.errors import VerificationUnavailable

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class ServiceCredentials:
    client_id: str
    client_secret: str
    audience: str
    scopes: tuple[str, ...] = ()


class ServiceTokenProvider:
    """Кэширующий обмен client credentials на audience-bound token."""

    def __init__(
        self,
        iam_base_url: str,
        credentials: ServiceCredentials,
        *,
        client: httpx.AsyncClient | None = None,
        # Насколько раньше срока обновляем токен, чтобы не предъявить
        # протухший на границе.
        refresh_margin_seconds: float = 30.0,
        request_timeout_seconds: float = 3.0,
        clock: Clock = _utcnow,
    ) -> None:
        if not credentials.client_id or not credentials.client_secret:
            raise VerificationUnavailable("service_credentials_not_configured")
        self._base_url = iam_base_url.rstrip("/")
        self._credentials = credentials
        self._client = client
        self._owns_client = client is None
        self._margin = refresh_margin_seconds
        self._timeout = request_timeout_seconds
        self._clock = clock
        self._token: str = ""
        self._expires_at: datetime | None = None

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    def _is_fresh(self) -> bool:
        if not self._token or self._expires_at is None:
            return False
        return self._clock() + timedelta(seconds=self._margin) < self._expires_at

    async def __call__(self) -> str:
        if self._is_fresh():
            return self._token
        return await self.refresh()

    async def refresh(self) -> str:
        try:
            response = await self._http().post(
                f"{self._base_url}/api/v1/tokens/exchange",
                json={
                    "clientId": self._credentials.client_id,
                    "clientSecret": self._credentials.client_secret,
                    "audience": self._credentials.audience,
                    "scopes": list(self._credentials.scopes),
                },
            )
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            # Причина не пересказывается: в ней может оказаться эхо запроса
            # вместе с секретом.
            raise VerificationUnavailable("service_token_exchange_failed") from exc

        token = str(body.get("accessToken") or "")
        expires_in = int(body.get("expiresIn") or 0)
        if not token or expires_in <= 0:
            raise VerificationUnavailable("service_token_malformed")

        self._token = token
        self._expires_at = self._clock() + timedelta(seconds=expires_in)
        return token

    def forget(self) -> None:
        """Сбросить кэш — например, после 401 от resource service."""
        self._token = ""
        self._expires_at = None
