# Configuration

rung reads `rung.toml` from the root of the audited repository, or the file given with
`--config`. With neither, the defaults below apply. Loading is read-only.

```toml
[rung]
fail_on = "high"          # critical | high | medium | low | info
stage_threshold = 0.7     # 0 < x <= 1
max_commits = 5000        # >= 1

[rules]
disable = ["COM004"]
[rules.severity]
DOC003 = "low"

[paths]
ignore = ["vendor/**", "**/*.min.js"]

[baseline]
file = "rung-baseline.json"
```

| Key | Default | Meaning |
| --- | --- | --- |
| `rung.fail_on` | `"high"` | `rung audit` exits 1 when a reported finding is at or above this severity, *after* stage-aware adjustment. `--fail-on` overrides it. |
| `rung.stage_threshold` | `0.7` | Share of a stage's applicable rules (by weight) that must pass for the stage to be met. |
| `rung.max_commits` | `5000` | Newest commits read for the history rules. Lower it for very deep histories. |
| `rules.disable` | `[]` | Rule ids that do not run. They are absent from the report and from every score. |
| `rules.severity` | `{}` | Rule id → severity. Replaces the rule's default and is also a ceiling for the rule's per-hit severities: a hit the rule marked lower stays lower, a hit it marked higher is brought down to the configured value. |
| `paths.ignore` | `[]` | Globs hidden from every rule (`**` crosses directories, `*` does not; case-insensitive). |
| `baseline.file` | none | JSON file of accepted findings, resolved relative to the config file. |

## Errors (exit code 2)

- A wrong type or value (`fail_on = "bogus"`, `stage_threshold = 0`, `disable = "COM004"`),
  invalid TOML, or a missing `--config` file.
- A baseline file that is missing, not JSON, or has an entry without a non-blank
  `justification`.
- A rule id in `rules.disable`, `rules.severity` or the baseline that no rule has. Ids are
  checked by the engine against the rule registry, so the message names the unknown id.

Unknown keys and tables are ignored, so a config written for a newer rung still loads.

## Baseline workflow

A baseline accepts existing findings so that CI only fails on new ones.

```bash
rung baseline . --output ../rung-baseline.json --justification "accepted for the pilot"
```

```json
[
  {
    "fingerprint": "3f2a9c0d1e4b5a6c7d8e",
    "rule_id": "DOC004",
    "justification": "accepted for the pilot",
    "path": "LICENSE"
  }
]
```

- `fingerprint`, `rule_id` and `justification` are required; `path` is informational, for
  people reviewing the file. A finding is suppressed when both fingerprint and rule id match.
- Fingerprints hash the rule id, the path and the text of the offending line (the message
  when there is no line), so they survive unrelated edits above the finding.
- Suppressed findings move to `suppressed` in the report (and carry `suppressions` in
  SARIF). They do not count in severity totals or the exit code. **The rule still counts
  as failed** in the scores, the stage and the checklist: a baseline hides noise, it does
  not award credit.
- Entries that match nothing are ignored. Re-running `rung baseline` with the baseline
  configured keeps the existing justifications and drops stale entries.
- `rung baseline` and `rung audit --output` refuse to write inside the audited repository
  unless `--allow-write-in-repo` is passed. If you commit the baseline into the repo, pass
  that flag knowingly.
