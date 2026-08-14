"""JWKS с кэшем, ротацией и bounded stale window.

Resource service не может ходить в IAM за ключом на каждый запрос — это
ставит его доступность в зависимость от чужого сервиса на горячем пути. Но и
держать ключ вечно нельзя: тогда ротация подписи ничего не отзывает.

Компромисс здесь трёхуровневый:

* `refresh_after` — мягкий срок: кэш ещё годен, но при первом промахе по `kid`
  делается принудительное обновление;
* `min_refresh_interval` — защита от того, чтобы поток запросов с неизвестным
  `kid` превратился в DDoS по JWKS-эндпоинту IAM;
* `stale_after` — жёсткая граница. Дольше неё непроверенный кэш не живёт:
  сервис отвечает `verification_unavailable`, а не принимает токен на веру.

Последний пункт — сознательный выбор доступности в пользу безопасности:
недоступный IAM закрывает вход, а не открывает его.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
from jwt import PyJWK
from jwt.algorithms import RSAAlgorithm

from platform_auth.errors import InvalidToken, VerificationUnavailable

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class JwksPolicy:
    refresh_after_seconds: float = 300.0
    stale_after_seconds: float = 3600.0
    min_refresh_interval_seconds: float = 10.0
    request_timeout_seconds: float = 3.0


class JwksCache:
    """Кэш публичных ключей одного issuer."""

    def __init__(
        self,
        jwks_url: str,
        *,
        client: httpx.AsyncClient | None = None,
        policy: JwksPolicy | None = None,
        clock: Clock = _utcnow,
    ) -> None:
        self._url = jwks_url
        self._client = client
        self._owns_client = client is None
        self._policy = policy or JwksPolicy()
        self._clock = clock
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: datetime | None = None
        self._last_attempt_at: datetime | None = None
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._policy.request_timeout_seconds)
        return self._client

    def _age_seconds(self) -> float | None:
        if self._fetched_at is None:
            return None
        return (self._clock() - self._fetched_at).total_seconds()

    def _is_stale(self) -> bool:
        age = self._age_seconds()
        return age is None or age > self._policy.stale_after_seconds

    def _may_attempt_refresh(self) -> bool:
        if self._last_attempt_at is None:
            return True
        elapsed = (self._clock() - self._last_attempt_at).total_seconds()
        return elapsed >= self._policy.min_refresh_interval_seconds

    async def key_for(self, kid: str) -> PyJWK:
        """Вернуть ключ по `kid`, обновив кэш при необходимости.

        Неизвестный `kid` — штатная ситуация сразу после ротации, поэтому он
        вызывает обновление. Но только одно на `min_refresh_interval`.
        """
        cached = self._keys.get(kid)
        age = self._age_seconds()
        fresh_enough = age is not None and age <= self._policy.refresh_after_seconds
        if cached is not None and fresh_enough:
            return cached

        if cached is None or not fresh_enough:
            await self._refresh_if_allowed()

        if self._is_stale():
            # Кэш не подтверждали дольше жёсткой границы: доверять ему нельзя.
            raise VerificationUnavailable("jwks_stale")

        key = self._keys.get(kid)
        if key is None:
            raise InvalidToken("unknown_key_id", details={"kid": kid})
        return key

    async def _refresh_if_allowed(self) -> None:
        async with self._lock:
            if not self._may_attempt_refresh():
                return
            self._last_attempt_at = self._clock()
            try:
                response = await self._http().get(self._url)
                response.raise_for_status()
                document: Any = response.json()
                keys = self._parse(document)
            except (httpx.HTTPError, ValueError, KeyError, jwt.PyJWTError):
                # Промах обновления сам по себе не отказ: пока кэш внутри
                # stale window, сервис продолжает работать на нём.
                return
            if not keys:
                return
            self._keys = keys
            self._fetched_at = self._clock()

    @staticmethod
    def _parse(document: Any) -> dict[str, PyJWK]:
        keys: dict[str, PyJWK] = {}
        for entry in document.get("keys", []):
            kid = entry.get("kid")
            if not kid:
                continue
            if entry.get("kty") != "RSA":
                # Симметричные ключи в JWKS для проверки RS256 бессмысленны и
                # опасны: их принятие открывает подмену алгоритма.
                continue
            keys[str(kid)] = PyJWK.from_dict(entry)
        return keys

    def seed(self, document: Any, *, fetched_at: datetime | None = None) -> None:
        """Заполнить кэш без сети — для тестов и для статической конфигурации."""
        self._keys = self._parse(document)
        self._fetched_at = fetched_at or self._clock()


class StaticKeySet:
    """Один заранее известный public key.

    Нужен там, где JWKS-эндпоинт недоступен по сети (изолированный контур), и
    ключ доставляется конфигурацией. Ротация в этом режиме — обязанность
    деплоя, поэтому режим считается исключением, а не нормой.
    """

    def __init__(self, public_key_pem: str, *, key_id: str = "") -> None:
        if not public_key_pem:
            raise VerificationUnavailable("public_key_not_configured")
        algorithm = RSAAlgorithm(RSAAlgorithm.SHA256)
        prepared = algorithm.prepare_key(public_key_pem)
        document = dict(algorithm.to_jwk(prepared, as_dict=True))
        document.update({"alg": "RS256", "use": "sig"})
        self._jwk = PyJWK.from_dict(document)
        self._key_id = key_id

    async def key_for(self, kid: str) -> PyJWK:
        if self._key_id and kid and kid != self._key_id:
            raise InvalidToken("unknown_key_id", details={"kid": kid})
        return self._jwk

    async def aclose(self) -> None:  # pragma: no cover - симметрия интерфейса
        return None


def utcnow() -> datetime:
    return _utcnow()


def stale_deadline(fetched_at: datetime, policy: JwksPolicy) -> datetime:
    return fetched_at + timedelta(seconds=policy.stale_after_seconds)
