# Contributing to rung

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest            # backend tests
ruff check src tests scripts && ruff format --check src tests scripts
cd web && npm ci && npm run lint && npm run build   # dashboard
```

## Adding a rule

1. Read `docs/architecture.md` ("Writing a rule" and "Stage assignment").
2. Add a function decorated with `@rule(...)` to the probe module for its dimension in
   `src/rung/probes/`. It registers itself; the engine needs no change.
3. Pick the `stage` where the practice becomes *expected*, not where it is nice to have.
4. Add at least one true-positive and one false-positive test in `tests/probes/`.
5. Document it in `docs/rules/<dimension>.md`: what it detects, why it matters, how to
   fix it, how to suppress it.

Ground rules: rules are pure functions of the `RepoSnapshot` (no network, no wall clock,
no writes); when unsure, lower the confidence instead of raising the severity; never put a
secret value in a message. Use only obviously fake credentials in tests, assembled at
runtime.

## Commits and pull requests

- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- Small, focused pull requests; CI must be green (lint, tests, dashboard build, self-audit).
- Changing a field of `AuditReport` is a breaking change to the output schema: bump
  `SCHEMA_VERSION` and note it in `CHANGELOG.md`.
