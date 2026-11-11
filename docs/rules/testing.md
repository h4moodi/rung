# Testing rules (TST)

Tests are recognised by naming and location conventions for Python, JS/TS, Go, JVM languages, Ruby, Rust, PHP, C#, Elixir, Dart and Swift; nothing is executed. Thresholds are module constants in `rung/probes/testing.py`: ratio 0.15 (from 10 source files), 10% of the last 100 non-merge commits (from 30 commits), 20% language share for TST008.

| Rule | Stage | Severity | Detects | Why it matters | How to fix |
| --- | --- | --- | --- | --- | --- |
| TST001 | stabilization | medium | Automated tests exist | After the first release every change risks breaking paying users; automated tests are the cheapest way to keep a released product dependable. | Add a test suite (e.g. a tests/ directory) covering the core behaviour. |
| TST002 | stabilization | low | Test runner configured | Tests only stabilise a product if anyone (and CI) can run them with one documented command; a declared runner makes that command explicit. | Declare the runner in the project manifest (pytest in pyproject.toml, a real `scripts.test` in package.json, a `test` Makefile target, ...). |
| TST003 | growth | medium | Test suite is proportionate to the code | As the team and codebase grow, a token test suite stops protecting anything; the amount of test code should keep pace with the amount of product code. | Add tests until there is roughly one test file per 7 source files. |
| TST004 | growth | low | Coverage measurement configured | With several contributors nobody knows which code is untested unless it is measured; coverage reporting keeps test gaps visible as the product grows. | Configure coverage (pytest-cov, jest --coverage, jacoco, `go test -cover`, ...) and report it in CI. |
| TST005 | stabilization | low | Linter or formatter configured | A linter catches whole classes of defects before they are released and keeps the code readable for whoever joins next. | Add and configure a linter/formatter for the main language (ruff, eslint + prettier, golangci-lint, ...). |
| TST006 | growth | low | Tests are maintained alongside code | A test suite written once and then abandoned drifts away from the product; in a scaling team, tests must change in the same commits as the code they protect. | Make tests part of the definition of done: change or add tests in the same commit/PR as the code. |
| TST007 | maturity | low | More than one test level | Unit tests alone do not show that an established product works end to end; mature teams add integration, end-to-end, contract or performance tests on top. | Add a second test level, e.g. tests/integration or an e2e suite (Playwright, Cypress, k6). |
| TST008 | maturity | low | Static type checking configured | In dynamically typed languages a type checker finds interface mistakes that tests miss and makes large, long-lived codebases safe to refactor. | Configure mypy or pyright for Python, and enable `"strict": true` in tsconfig.json for TypeScript. |

## How to suppress

Disable a rule for the whole repository in `rung.toml`:

```toml
[rules]
disable = ["TST008"]
```

To accept a single finding instead, add its fingerprint to the baseline file
(`rung baseline --output rung-baseline.json --justification "..."`); every baseline entry
needs a non-empty `justification`. Severity can be changed per rule under `[rules.severity]`.
