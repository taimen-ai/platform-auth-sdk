# Platform Auth SDK

Product-neutral Enforcement SDK для resource services платформы. Даёт одинаковый
Policy Enforcement Point поверх отдельных `iam-service` и `entitlement-service`,
не привнося в них доменную модель продукта.

Канонические границы — ADR-0013: IAM подтверждает identity, Entitlement выдаёт
лицензию, доменную политику применяет сам resource service. SDK связывает три
шага в один порядок и делает отказ одинаковым во всех сервисах.

## Что делает

- **validation** — RS256-подпись по JWKS с ротацией, точные issuer и audience,
  временные claims, обязательный набор полей;
- **trusted Auth Context** — identity строится только из проверенных claims;
- **revocation** — порт локальной политики отзыва плюс кэш с жёсткой границей
  устаревания;
- **entitlement** — decision API и двухфазная квота `reserve → consume|release`
  с bounded degraded mode;
- **deny contract** — один стабильный код клиенту, точная причина в audit;
- **audit envelope** — запись решения с корреляцией и без секретов.

## Чего не делает намеренно

SDK не содержит продуктовых permissions, не читает чужие базы данных и не знает
про Workspace, Project, Task или Memory namespace. Он не выпускает credentials и
не заменяет доменную авторизацию: `domain_check` — обязанность сервиса.

## Порядок enforcement

```
identity → revocation → entitlement → domain policy → transactional gates
```

Порядок не настраивается. Каждый следующий шаг дороже предыдущего и осмыслен
только после него: спрашивать лицензию для неподтверждённой identity незачем, а
доменное право нельзя вынести из продукта.

```python
from platform_auth import (
    JwksCache, PolicyEnforcementPoint, TokenVerifier, VerifierConfig,
)

keys = JwksCache("https://iam.example/.well-known/jwks.json")
verifier = TokenVerifier(keys, VerifierConfig(
    issuer="https://iam.example", audience="control-plane",
))
pep = PolicyEnforcementPoint(verifier, entitlement=..., revocation=..., audit=...)

allowed = await pep.enforce_authorization_header(
    request.headers.get("authorization"),
    action="tasks.create",
    feature="tasks",
    required_scopes=("write",),
    domain_check=check_domain_permissions,
    correlation_id=request_id,
)
```

## Fail closed

Все режимы недоступности закрывают вход, а не открывают его:

| Ситуация | Ответ |
|---|---|
| JWKS недоступен дольше `stale_after` | `verification_unavailable` (503) |
| Источник revocation молчит дольше окна | `verification_unavailable` (503) |
| Entitlement недоступен, кэш просрочен | `entitlement_unavailable` (503) |
| Любой дефект токена | `invalid_token` (401) |
| Нет scope / лицензии / права | `insufficient_scope` / `not_entitled` / `permission_denied` (403) |

Все дефекты токена схлопываются в один код: разные ответы превратили бы
endpoint в оракул по чужим credential. Точная причина уходит в audit.

Degraded mode ограничен дважды: по возрасту записи и по её содержанию.
Устаревшее решение нельзя применить к запросу с бо́льшим `required_amount` —
иначе кэш становится способом обойти квоту во время сбоя.

## Разработка

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy
```

`platform_auth.testing` даёт потребителю SDK генератор ключей, выпуск токена с
произвольными claims и управляемые часы — чтобы каждый сервис не писал свой
вариант и они не разошлись.
