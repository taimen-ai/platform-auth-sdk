# Platform Auth SDK

Product-neutral Enforcement SDK для resource services платформы. Даёт одинаковый
Policy Enforcement Point поверх отдельных `iam-service`, `entitlement-service` и
`policy-service`, не привнося в них доменную модель продукта.

Канонические границы — ADR-0013 и ADR-0025: IAM подтверждает identity,
Entitlement выдаёт лицензию, policy-service решает организационную
авторизацию, транзакционные гейты применяет сам resource service. SDK
связывает шаги в один порядок и делает отказ одинаковым во всех сервисах.

## Что делает

- **validation** — RS256-подпись по JWKS с ротацией, точные issuer и audience,
  временные claims, обязательный набор полей;
- **trusted Auth Context** — identity строится только из проверенных claims;
- **revocation** — порт локальной политики отзыва плюс кэш с жёсткой границей
  устаревания;
- **entitlement** — decision API и двухфазная квота `reserve → consume|release`
  с bounded degraded mode;
- **policy** — контракт Policy Decision Point: `check` / `batch_check` /
  `list_objects` / `list_subjects` с кэшем в пределах TTL и без grace-окна;
- **deny contract** — один стабильный код клиенту, точная причина в audit;
- **audit envelope** — запись решения с корреляцией и без секретов.

## Чего не делает намеренно

SDK не содержит продуктовых permissions, не читает чужие базы данных и не знает
про Workspace, Project, Task или Memory namespace. Он не выпускает credentials и
не считает организационную политику сам — только спрашивает policy-service;
транзакционные гейты (`domain_check`) — обязанность сервиса.

## Порядок enforcement

```
identity → revocation → entitlement → policy → transactional gates (domain_check)
```

Порядок не настраивается. Каждый следующий шаг дороже предыдущего и осмыслен
только после него: спрашивать лицензию для неподтверждённой identity незачем, а
доменное право нельзя вынести из продукта.

```python
from platform_auth import (
    JwksCache,
    PolicyEnforcementPoint,
    TokenVerifier,
    VerifierConfig,
)

keys = JwksCache("https://iam.example/.well-known/jwks.json")
verifier = TokenVerifier(
    keys,
    VerifierConfig(
        issuer="https://iam.example",
        audience="control-plane",
    ),
)
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

## Стадия policy

Организационную авторизацию («может ли principal P выполнить действие A над
ресурсом R» с учётом дерева воркспейсов, отношений и делегирования) считает
внешний `policy-service` (ADR-0025). В PEP стадия включается передачей
`resource`: ресурс — только серверно найденный `type:id`, клиентские claims о
нём не принимаются. Мутации и privileged actions проверяются с
`policy_consistency="strong"` — без кэша.

```python
from platform_auth import AuthorizationClient, ContextualTuple, ResourceRef

authorization = AuthorizationClient(
    "https://policy.example",
    service_tokens.token_for("policy-service"),  # audience policy-service
)
pep = PolicyEnforcementPoint(verifier, entitlement=..., authorization=authorization)

allowed = await pep.enforce_authorization_header(
    request.headers.get("authorization"),
    action="tasks.update",
    resource=ResourceRef("task", task.id),
    contextual=(ContextualTuple(f"task:{task.id}", "scope", f"workspace:{ws}"),),
    policy_consistency="strong",
)
allowed.policy  # PolicyDecision: reason_code, decision_id, model_version, source
```

Клиент сам по себе даёт `check`, `batch_check` (до 100 элементов),
`list_objects` (постранично, для фильтрации списков) и `list_subjects` (для
маршрутизации Approval). Кэшируется только `check` с обычной согласованностью,
не дольше `cache_ttl_seconds` (по умолчанию 5 с); `invalidate(tenant_id)` —
точка подключения подписки на события `binding.*`. Вызов от имени конечного
пользователя — `on_behalf_of`, для него service identity нужен scope
`policy:check-on-behalf`.

Отсутствие настройки не открывает доступ: `resource` без сконфигурированного
клиента даёт `authorization_unavailable`, а `NullAuthorizationClient` отвечает
`deny` с `source="disabled"` — в отличие от `NullEntitlementClient`, потому
что «лицензия не ограничена» и «права никто не проверил» — разные вещи.

## Fail closed

Все режимы недоступности закрывают вход, а не открывают его:

| Ситуация | Ответ |
|---|---|
| JWKS недоступен дольше `stale_after` | `verification_unavailable` (503) |
| Источник revocation молчит дольше окна | `verification_unavailable` (503) |
| Entitlement недоступен, кэш просрочен | `entitlement_unavailable` (503) |
| policy-service недоступен, отклонил запрос или не настроен при переданном `resource` | `authorization_unavailable` (503) |
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
