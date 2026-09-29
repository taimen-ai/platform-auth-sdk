# Contributing to Taimen Platform Auth SDK

Thank you for taking the time to contribute. Taimen is an organizational
runtime in which people, AI agents, workflows and services execute the work
of an organization; the platform is developed in the open under the
Apache License 2.0. This repository holds the Platform Auth SDK: the
product-neutral enforcement library (token validation, trusted Auth Context,
revocation, entitlement and policy decisions, uniform deny contract) shared by
the Taimen resource services.

## Before you start

- Read the [Product Vision](https://github.com/monthu56/taimen/blob/main/docs/product-vision.md)
  and the [ADR registry](https://github.com/monthu56/taimen/blob/main/docs/adr/README.md)
  of the umbrella repository. Architecture decisions are recorded as ADRs (in
  Russian, with an English title line); English summaries are provided on
  request in the ADR's discussion.
- The SDK has no ADR series of its own: the decisions that shape it live in the
  umbrella registry. Start with ADR-0013 (separate IAM and Entitlement
  services) and ADR-0025 (authorization model and policy-service), which fix
  the enforcement order `identity → revocation → entitlement → policy →
  transactional gates` that the SDK implements.
- Check the [roadmap](https://github.com/monthu56/taimen/blob/main/docs/roadmap.md)
  and open issues before starting a large change. For anything that changes
  the public API of `platform_auth`, the deny contract or the enforcement
  order, open an issue first and propose an ADR in the umbrella repository.

## Contributor License Agreement

We require a signed Contributor License Agreement (CLA) for every
contribution, so that the project can be relicensed or defended without
tracking down every author. The CLA is checked by cla-assistant on each pull
request; you sign once.

- Individuals: [`cla/CLA-individual.md`](https://github.com/monthu56/taimen/blob/main/cla/CLA-individual.md)
- Companies contributing on behalf of employees: [`cla/CLA-entity.md`](https://github.com/monthu56/taimen/blob/main/cla/CLA-entity.md)

The CLA grants the project a copyright and patent licence to your
contribution; you keep your copyright.

## Development setup

The SDK is a pure Python library (Python 3.12+, [uv](https://docs.astral.sh/uv/),
hatchling build backend). It needs no database and no running services: the
tests use `platform_auth.testing` (key generation, token issuance with
arbitrary claims, controllable clock) and in-memory fakes.

```bash
git clone <this-repository-url> platform-auth-sdk && cd platform-auth-sdk
uv sync                       # runtime dependencies + the `dev` group (pytest, ruff, mypy)
uv run pytest                 # tests (asyncio_mode = auto)
uv run ruff check .           # lint
uv run ruff format --check .  # formatting
uv run mypy                   # strict typing of `platform_auth`
uv build                      # sdist + wheel into dist/ (not committed)
```

The package is typed (`py.typed`) and checked with `mypy --strict`; new public
API must keep that clean. Existing comments and docstrings are written in
Russian, which is why ruff's confusable-character checks (`RUF001`–`RUF003`)
are disabled; either language is fine in new code.

The SDK is consumed by other Taimen components (`control-plane`,
`memory-service`, `policy-service`, `process-runtime`) as a **path dependency**
`../platform-auth-sdk`, so a change here is visible to them without a release.
When you change the public API or the deny contract, check out the umbrella
repository (`git clone --recurse-submodules`) and run the consumers' tests as
well (`make check` in the umbrella runs ruff and tests of every Python
component, as in CI).

## Pull requests

- One logical change per pull request; keep the history linear (rebase, no
  merge commits).
- Tests and `ruff check` / `ruff format --check` / `mypy` must pass; behaviour
  changes come with tests.
- Commit messages explain *why*, not *what*; reference the ADR or issue.
- Public API changes (names exported from `platform_auth`, error codes of the
  deny contract, configuration fields, `platform_auth.testing` helpers) update
  the README and, when they break compatibility, the platform's
  [`docs/migration-vX.Y.md`](https://github.com/monthu56/taimen/blob/main/docs/)
  in the umbrella repository.
- Fail-closed behaviour is a contract: every unavailability path of the SDK
  denies access (see "Fail closed" in the README). A change that opens access
  on failure will not be accepted without an ADR.
- The pull request template asks you to confirm the CLA and that no secrets,
  customer data or internal hostnames are included.

## Reporting bugs and security issues

Bugs: open an issue in this repository with the version, steps to reproduce
and logs. Security issues: see [SECURITY.md](SECURITY.md) and do not open a
public issue.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
