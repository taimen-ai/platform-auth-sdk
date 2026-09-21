# Platform Auth SDK

*English. Russian version: [README.ru.md](README.ru.md)*

Product-neutral Enforcement SDK for the platform's resource services. It provides
the same Policy Enforcement Point on top of the separate `iam-service`,
`entitlement-service` and `policy-service` without bringing a product's domain
model into them.

The canonical boundaries are ADR-0013 and ADR-0025: IAM confirms identity,
Entitlement issues the license, policy-service decides organizational
authorization, and transactional gates are applied by the resource service
itself. The SDK chains these steps into a single order and makes denial
identical across all services.

## What it does

- **validation** — RS256 signature against JWKS with key rotation, exact issuer
  and audience, time-based claims, a mandatory set of fields;
- **trusted Auth Context** — identity is built only from verified claims;
- **revocation** — a port for a local revocation policy plus a cache with a hard
  staleness bound;
- **entitlement** — decision API and a two-phase quota `reserve → consume|release`
  with bounded degraded mode;
- **policy** — Policy Decision Point contract: `check` / `batch_check` /
  `list_objects` / `list_subjects` with a cache within the TTL and no grace window;
- **deny contract** — one stable code for the client, the exact reason in audit;
- **audit envelope** — a record of the decision with correlation and without
  secrets.

## What it deliberately does not do

The SDK contains no product permissions, does not read other services' databases
and knows nothing about Workspace, Project, Task or Memory namespace. It does not
issue credentials and does not compute organizational policy itself — it only
asks policy-service; transactional gates (`domain_check`) are the service's
responsibility.

## Enforcement order

```
identity → revocation → entitlement → policy → transactional gates (domain_check)
```

The order is not configurable. Each subsequent step is more expensive than the
previous one and only makes sense after it: there is no point in asking for a
license for an unconfirmed identity, and a domain permission cannot be moved out
of the product.

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

## The policy stage

Organizational authorization ("may principal P perform action A on resource R",
taking into account the workspace tree, relations and delegation) is computed by
the external `policy-service` (ADR-0025). In the PEP the stage is enabled by
passing `resource`: the resource is only a server-side resolved `type:id`; client
claims about it are not accepted. Mutations and privileged actions are checked
with `policy_consistency="strong"` — bypassing the cache.

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

On its own the client provides `check`, `batch_check` (up to 100 items),
`list_objects` (paginated, for filtering lists) and `list_subjects` (for
Approval routing). Only `check` with regular consistency is cached, for no longer
than `cache_ttl_seconds` (5 s by default); `invalidate(tenant_id)` is the hook
for subscribing to `binding.*` events. A call on behalf of an end user is
`on_behalf_of`; for it the service identity needs the `policy:check-on-behalf`
scope.

A missing configuration does not open access: `resource` without a configured
client yields `authorization_unavailable`, and `NullAuthorizationClient` answers
`deny` with `source="disabled"` — unlike `NullEntitlementClient`, because "the
license is unrestricted" and "nobody checked the permissions" are different
things.

## Fail closed

All unavailability modes close the door rather than open it:

| Situation | Response |
|---|---|
| JWKS unavailable for longer than `stale_after` | `verification_unavailable` (503) |
| The revocation source is silent for longer than the window | `verification_unavailable` (503) |
| Entitlement unavailable, cache expired | `entitlement_unavailable` (503) |
| policy-service unavailable, rejected the request, or not configured while `resource` was passed | `authorization_unavailable` (503) |
| Any token defect | `invalid_token` (401) |
| No scope / license / permission | `insufficient_scope` / `not_entitled` / `permission_denied` (403) |

All token defects collapse into a single code: distinct responses would turn the
endpoint into an oracle for other people's credentials. The exact reason goes to
audit.

Degraded mode is bounded twice: by the age of the record and by its content. A
stale decision cannot be applied to a request with a larger `required_amount` —
otherwise the cache becomes a way to bypass the quota during an outage.

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy
```

`platform_auth.testing` gives the SDK consumer a key generator, token issuance
with arbitrary claims and a controllable clock — so that each service does not
write its own variant and they do not drift apart.
