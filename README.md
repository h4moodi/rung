# rung

**Stage-aware repository auditing.** rung inspects a Git repository, works out which
life-cycle stage its engineering practices have actually reached, and tells you what to fix
to climb to the next rung.

Most audit tools grade every project against the same mature open-source checklist, so an
MVP gets buried in findings it has no business caring about yet. rung grades against the
start-up progression model of Klotins et al. (IEEE TSE, 2021): **inception → stabilization
→ growth → maturity**. A missing security policy is noise for a two-week-old prototype and
a real gap for a product with paying customers; rung reports it accordingly.

```
 repo ──► collect ──► analyze (6 probes, 61 rules) ──► classify stage ──► checklist
          read-only    commit history · containers · tests          ladder of          prioritized:
                       CI/CD · documentation · security             four rungs         overdue → next → later
```

## Install

Requires Python 3.11+ and `git`.

```bash
git clone https://github.com/h4moodi/rung && cd rung
python -m venv .venv && . .venv/bin/activate
pip install -e ".[api]"        # drop [api] if you only want the CLI
```

## Quick start

```bash
rung audit path/to/repo                       # human-readable report
rung audit . --format json --output ../report.json
rung audit . --format sarif --output ../rung.sarif # GitHub code scanning
rung audit . --fail-on medium                 # CI gate
rung rules                                    # every rule, its stage and severity
rung stages                                   # what each stage expects
```

Example (rung auditing itself):

```
╭─ rung ───────────────────────────────────────────────────────────────────────╮
│ rung  @ 4a962b1557                                                           │
│ Stage: MATURITY  (rung 4 of 4)                                               │
│ Next rung: none, top of the ladder                                           │
│ Overall score: 92.5 / 100                                                    │
│ Classified as maturity: every stage up to it meets the 70% threshold         │
│ (inception 100%, stabilization 100%, growth 87%, maturity 74%).              │
╰──────────────────────────────────────────────────────────────────────────────╯

Progression ladder ─────────────────────────────────────────────────────────────
  ✔  maturity       ███████████████░░░░░   74%  7/10   ◀ you are here
  ✔  growth         █████████████████░░░   87%  14/16
  ✔  stabilization  ████████████████████  100%  14/14
  ✔  inception      ████████████████████  100%  9/9
  A rung is met at 70% of its applicable rules, by weight; rungs must be climbed
  in order.

Dimension scores ───────────────────────────────────────────────────────────────
  Commit history    ████████████████████  100.0  0 pass, 0 fail, 10 n/a
  Containerization  ████████████████████  100.0  10 pass, 0 fail, 0 n/a
  Testing           ███████████████░░░░░   75.0  5 pass, 2 fail, 1 n/a
  CI/CD             ██████████████████░░   91.3  8 pass, 1 fail, 0 n/a
  Documentation     ███████████████████░   95.5  10 pass, 1 fail, 0 n/a
  Security          ███████████████████░   94.3  11 pass, 1 fail, 1 n/a
```

`--output` refuses to write inside the audited repository unless you pass
`--allow-write-in-repo`, which keeps the read-only guarantee honest.

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` tool or
configuration error.

## How the diagnosis works

Each rule belongs to one of six dimensions and to the stage where its practice becomes
*expected*:

| Stage | Situation | rung expects from here on |
| --- | --- | --- |
| inception | Idea to first release | Real version control use, README, .gitignore, declared dependencies, no committed secrets |
| stabilization | Released; make it dependable | Tests, CI on every push/PR, reproducible builds, lockfiles, license, setup docs |
| growth | Team and customers scale | Review workflow, several contributors, lint in CI, hardened containers, contributing guide, changelog, release tags, dependency automation |
| maturity | Established; optimize and govern | Security policy, SHA-pinned actions, least-privilege CI, health checks, architecture docs, release cadence, low bus-factor risk |

- A stage is **met** when at least 70 % (configurable) of its applicable rules pass, by weight.
- The classified stage is the highest rung with every rung below it also met: you cannot
  skip tests and call yourself mature.
- **Stage-aware severity:** gaps at or below your stage are *overdue*, gaps on the next
  rung are *next*, and anything further up is reported as `info` so it does not drown out
  what matters now. Dangerous things (committed credentials, private keys) are expected
  from inception and are never down-ranked.
- The **checklist** orders failed rules by priority, then severity, then weight.

Details and a worked example: [docs/scoring.md](docs/scoring.md).

## Guarantees

- **Read-only.** rung never modifies the audited repository and never runs its code.
- **Deterministic.** Same commit + same config ⇒ same report (only `duration_ms` differs).
  No network access during analysis.
- **Evidence-based.** Every finding carries a path, a line where one exists, the rule id
  and why it matters.
- **No secret leakage.** Detected credentials are reported by type and location with a
  redacted preview, never the value.

## Dashboard and API

```bash
rung serve                       # API on http://127.0.0.1:8000
cd web && npm ci && npm run dev  # dashboard on http://localhost:3000
```

or both with Docker:

```bash
docker compose up --build
```

The dashboard shows the stage ladder, per-dimension scores, the checklist (tick items off
as you go), a filterable findings table and every rule's outcome. `/sample` renders a
bundled report without a backend. The API has no authentication in v1 and clones
repositories on request: keep it on localhost or a trusted network
([docs/api.md](docs/api.md)).

## Configuration

Put a `rung.toml` in the audited repository or pass `--config`:

```toml
[rung]
fail_on = "high"          # critical | high | medium | low | info
stage_threshold = 0.7
max_commits = 5000

[rules]
disable = ["COM004"]
[rules.severity]
DOC004 = "low"

[paths]
ignore = ["vendor/**", "**/*.min.js"]

[baseline]
file = "rung-baseline.json"   # accepted findings; every entry needs a justification
```

Create a baseline with
`rung baseline . --output rung-baseline.json --justification "accepted for the pilot"`.
Full reference: [docs/configuration.md](docs/configuration.md).

## Use in CI

```yaml
- run: pip install rung   # or: pip install git+https://github.com/h4moodi/rung
- run: rung audit . --format sarif --output "$RUNNER_TEMP/rung.sarif" --fail-on high
- uses: github/codeql-action/upload-sarif@<commit-sha>
  if: always()
  with:
    sarif_file: ${{ runner.temp }}/rung.sarif
```

Check out with `fetch-depth: 0`: on a shallow clone the commit-history rules are reported
as not applicable.

## Documentation

| | |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Pipeline, module map, invariants, how to write a rule |
| [docs/scoring.md](docs/scoring.md) | Classification and severity model |
| [docs/rules/](docs/rules/) | Every rule: what it detects, why, how to fix, how to suppress |
| [docs/configuration.md](docs/configuration.md) | `rung.toml` and baselines |
| [docs/output.md](docs/output.md) | Terminal, JSON schema, SARIF mapping, exit codes |
| [docs/api.md](docs/api.md) · [docs/dashboard.md](docs/dashboard.md) | Backend and web UI |
| [docs/evaluation.md](docs/evaluation.md) | Running the accuracy benchmark and the SUS study |

## Scope and limits

rung reads repository artifacts. By design it does not compile code, parse language ASTs,
execute anything, or measure runtime behaviour, and it does not query vulnerability
databases (that would make results depend on the day you run it). It complements tools
such as SonarQube and OpenSSF Scorecard rather than replacing them. The stage thresholds
and rule-to-stage mapping are a first operationalization of the progression model and are
meant to be calibrated against a benchmark set ([docs/evaluation.md](docs/evaluation.md)).

Only audit repositories you own or are authorized to assess.

## Background

rung is the CSE401A graduation project of Mohammed Shazad Hassan (Software Engineering,
University of Kurdistan Hewlêr), built with the Design Science Research method.

- E. Klotins et al., "A Progression Model of Software Engineering Goals, Challenges, and
  Practices in Start-Ups," *IEEE Transactions on Software Engineering*, 47(3), 2021.
- C. Giardino et al., "Software Development in Startup Companies: The Greenfield Startup
  Model," *IEEE Transactions on Software Engineering*, 42(6), 2016.

## License

[MIT](LICENSE)
