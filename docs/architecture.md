# rung architecture

rung audits a repository against the start-up progression model of Klotins et al.
(IEEE TSE 47(3), 2021): it inspects six repository artifacts, decides which life-cycle
stage (**inception → stabilization → growth → maturity**) the repo's engineering practices
have reached, and returns a prioritized checklist for climbing to the next rung.

## Pipeline

```
            collect                 analyze                          report
 repo ──► RepoSnapshot ──► rules (6 probe modules) ──► engine ──► terminal / JSON / SARIF
          (read-only)       run(repo) -> Check          │
                                                        ├─ scoring.classify   (stage ladder)
                                                        ├─ stage-aware severity
                                                        └─ scoring.checklist  (prioritized gaps)
 CLI (typer) ─┐
              ├─► engine.run_audit(path, config) -> AuditReport
 FastAPI ─────┘        └─► SQLite history ──► Next.js dashboard
```

| Module | Owns |
| --- | --- |
| `rung.models` | Every cross-module contract; `AuditReport` JSON is the public schema (`SCHEMA_VERSION`) |
| `rung.collect` | `RepoSnapshot`: read-only file + git-history access, symlink-escape safe |
| `rung.registry` | `@rule` decorator, `Registry`, `load_builtin_rules()` (auto-imports `rung.probes.*`) |
| `rung.probes.*` | One module per dimension: `commits`, `containers`, `tests`, `cicd`, `docs`, `security` |
| `rung.config` | `Config` model + `load_config()` for `rung.toml`, baseline file handling |
| `rung.scoring` | `classify()` (stage ladder), `score_dimensions()`, `build_checklist()` |
| `rung.engine` | `run_audit()`: orchestrates collect → analyze → score; isolates rule crashes |
| `rung.report` | `render_terminal()`, `to_json()`, `to_sarif()` |
| `rung.cli` | `rung audit / rules / stages / baseline / serve` |
| `rung.api` | FastAPI app, audit history store, safe remote cloning |
| `web/` | Next.js + Tailwind dashboard |

## Invariants (non-negotiable)

1. **Read-only.** Nothing in rung writes inside the audited repo. Git is invoked with
   `GIT_OPTIONAL_LOCKS=0`. Output files go where the user points `--output`.
2. **Deterministic.** Same repo + same commit + same config ⇒ byte-identical JSON except
   `summary.duration_ms`. No network in the analyze stage. Rules use `repo.head_date` as
   "now", never the wall clock. Iterate sorted collections only.
3. **Evidence-based.** Every finding has a path (the *expected* path for a missing
   artifact), a line/range when one exists, the rule id and a why-it-matters message.
4. **Low noise.** Unsure ⇒ lower `confidence`, never higher severity. A rule that cannot
   judge returns `Check.na(...)` and is excluded from scoring.
5. **No secret values** in findings, logs, exceptions or test output: use `rung.redact`.

## Writing a rule

```python
from rung.models import Check, Confidence, Dimension, Hit, Severity, Stage
from rung.registry import rule

@rule(
    id="DOC001", title="README present", dimension=Dimension.docs,
    stage=Stage.inception, severity=Severity.medium, confidence=Confidence.high,
    description="A README is the entry point for every new contributor and user.",
    remediation="Add a README.md describing what the project is and how to run it.",
)
def readme_present(repo):
    found = repo.find_named("README.md", "README.rst", "README.txt", "README", root_only=True)
    if found:
        return Check.ok(f"README found at {found[0]}", evidence=found[:1])
    return Check.fail("No README at the repository root", at="README.md")
```

- `Check.ok(summary, evidence=[paths|Location])`, `Check.fail(summary, hits=[Hit(...)])` or
  `Check.fail(summary, at="path", line=n)`, `Check.na(summary)`.
- `Hit(path, message, line, end_line, severity, confidence)`; per-hit severity/confidence
  override the rule's defaults.
- Rule ids: `COM0xx` commits, `CTR0xx` containers, `TST0xx` tests, `CIC0xx` CI/CD,
  `DOC0xx` docs, `SEC0xx` security. Ids are stable public API (config, baselines, SARIF).
- A rule must be a pure function of the snapshot: no globals, no network, no wall clock,
  no writes, bounded work (cap files/lines scanned and say so in the summary).

### Stage assignment

`stage` = the stage where the practice becomes *expected*, per the progression model:

| Stage | Start-up situation (Klotins et al.) | Practices rung expects from here on |
| --- | --- | --- |
| inception | Idea → first release; tiny team; speed over process | Real version control use, README, .gitignore, dependency manifest, no committed secrets |
| stabilization | Product released; make it dependable for first customers | Automated tests, CI on push/PR, reproducible build (Dockerfile, lockfile), LICENSE, setup docs, readable commit messages |
| growth | Team and customer base scale; process must scale too | PR/merge workflow, several contributors, CI runs tests + lint, hardened containers, CONTRIBUTING, changelog/roadmap, CODEOWNERS, dependency-update automation, release tags |
| maturity | Established product; optimize and govern | SECURITY.md, SHA-pinned actions, least-privilege CI tokens, healthchecks, architecture docs/ADRs, sustained release cadence, low bus-factor risk |

Things that are dangerous at any stage (committed credentials, private keys) are
`stage=inception` so they are never down-ranked.

## Scoring model (`rung.scoring`)

- **Rule outcome** `passed | failed | not_applicable`; n/a rules are ignored everywhere.
- **Dimension score** = 100 × Σ weight(passed) / Σ weight(applicable) per dimension
  (100 if nothing is applicable). **Overall score** = same ratio over all rules.
- **Stage fulfillment** F(s) = Σ weight(passed rules with stage == s) / Σ weight(applicable
  rules with stage == s); 1.0 if a stage has no applicable rules.
- **Classification (the ladder):** a stage is *met* when F(s) ≥ `stage_threshold`
  (default 0.70). The classified stage is the highest stage S such that every stage ≤ S is
  met. Inception is the floor: a repo that does not meet inception is still classified
  `inception` (its `StageProgress.met` is false and its gaps are `overdue`).
- **Stage-aware severity:** for a finding from a rule with stage R in a repo classified C:
  R ≤ C ⇒ `overdue`, severity = base; R == next(C) ⇒ `next`, severity = base;
  R beyond next(C) ⇒ `later`, severity = `info` (`base_severity` keeps the original).
  This is what stops rung from punishing an MVP for lacking enterprise governance.
- **Checklist:** one item per failed rule, ordered by priority (overdue, next, later), then
  base severity (worst first), then weight (heaviest first), then rule id.

## Engine contract (`rung.engine`)

```python
def run_audit(
    path: str | os.PathLike[str],
    *,
    config: Config | None = None,      # None -> load_config(path)
    registry: Registry | None = None,  # None -> load_builtin_rules()
    source: str | None = None,         # display name/URL for RepoInfo.source (default: path)
) -> AuditReport
```

A rule that raises is recorded as `not_applicable` with `RuleResult.error` set (type and
message only, no traceback, no file contents) and never aborts the audit.
Finding fingerprint = `fingerprint(rule_id, hit.path, anchor)` where anchor is the stripped
text of the hit line when it can be read, else the hit message.

## Config (`rung.toml` in the audited repo, or `--config`)

```toml
[rung]
fail_on = "high"          # exit 1 if any finding has severity >= this (after stage-aware adj.)
stage_threshold = 0.7
max_commits = 5000

[rules]
disable = ["COM004"]
[rules.severity]
DOC003 = "low"

[paths]
ignore = ["vendor/**", "**/*.min.js"]

[baseline]
file = "rung-baseline.json"   # [{"fingerprint": "...", "rule_id": "...", "justification": "..."}]
```

Baseline entries without a non-empty `justification` are a config error (exit 2).

## CLI contract

```
rung audit [PATH=.] [--format terminal|json|sarif] [--output FILE] [--fail-on SEVERITY]
                    [--config FILE] [--no-color]
rung rules [--format terminal|json]        # list every rule with stage/severity/dimension
rung stages                                 # explain the four stages
rung baseline [PATH=.] --output FILE --justification TEXT
rung serve [--host 127.0.0.1] [--port 8000] # run the API (needs the `api` extra)
```

Exit codes: `0` clean, `1` findings at/above threshold, `2` tool or config error.

## HTTP API (`rung.api.app:create_app`)

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | `{status, version}` |
| GET | `/api/rules` | rule catalogue |
| GET | `/api/stages` | stage definitions |
| POST | `/api/audits` | body `{"source": "<https git URL or allowed local path>"}` → `{id, report}` |
| GET | `/api/audits` | history: id, source, created_at, stage, overall_score, counts |
| GET | `/api/audits/{id}` | stored `AuditReport` |
| GET | `/api/audits/{id}/sarif` | SARIF 2.1.0 rendering |
| DELETE | `/api/audits/{id}` | remove from history |
