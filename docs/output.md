# Output

`rung audit` renders one `AuditReport` in three formats. Exit codes are the same for all.

| Exit code | Meaning |
| --- | --- |
| 0 | No reported finding at or above `fail_on` |
| 1 | At least one reported (non-suppressed) finding at or above `fail_on`, using stage-adjusted severity |
| 2 | Tool or configuration error: one line on stderr (`RUNG_DEBUG=1` adds the traceback) |

`--output FILE` writes the report to a file and keeps stdout empty. Writing inside the
audited repository is refused unless `--allow-write-in-repo` is given.

## Terminal

Header (repository, classified stage, next rung, overall score, rationale); the ladder
with each rung's fulfillment and a "you are here" marker; dimension score bars; the
checklist; findings grouped by severity as `RULE path:line` plus message; rule errors, if
any; a closing summary line. The checklist and each severity group show 15 entries unless
`--all` is passed. Colour is dropped for `--no-color`, `NO_COLOR` and non-TTY output.
Text from the repository is printed with control characters removed.

## JSON (`--format json`)

`AuditReport` as defined in `rung/models.py`, `tool.schema_version` = `1.0`. Key order is
fixed; the output is byte-identical between runs except `summary.duration_ms`.

| Field | Content |
| --- | --- |
| `tool` | `name`, `version`, `schema_version` |
| `repo` | `name`, `source`, `is_git`, `head_commit`, `head_date`, `branch`, `shallow` |
| `classification` | `stage`, `next_stage`, `threshold`, `rationale`, `progress[]` (`stage`, `fulfillment` 0-1, `passed`, `total`, `met`) |
| `overall_score` | 0-100 |
| `dimensions[]` | all six: `dimension`, `score`, `passed`, `failed`, `not_applicable` |
| `rules[]` | every rule that ran, by id: `rule_id`, `title`, `dimension`, `stage`, `weight`, `severity` (after config override), `confidence`, `outcome`, `summary`, `evidence[]`, `finding_count` (reported findings only), `error` |
| `findings[]` | sorted by severity, rule id, path, line: `rule_id`, `title`, `dimension`, `stage`, `severity` (stage-adjusted), `base_severity`, `confidence`, `message`, `remediation`, `location` (`path`, `start_line`, `end_line`), `fingerprint` |
| `checklist[]` | `rank`, `rule_id`, `title`, `dimension`, `stage`, `priority`, `severity`, `remediation`, `finding_count` |
| `suppressed[]` | `fingerprint`, `rule_id`, `path`, `justification` |
| `summary` | `counts_by_severity`, `rules_run`, `rules_passed`, `rules_failed`, `rules_not_applicable`, `files_scanned`, `commits_analyzed`, `suppressed`, `duration_ms` |

A rule that crashed has `outcome: not_applicable` and `error: "<Type>: <message>"`.
Disabled rules are not listed.

## SARIF (`--format sarif`)

SARIF 2.1.0, accepted by GitHub code scanning.

| SARIF | Source |
| --- | --- |
| `tool.driver.rules[]` | every rule that ran: `id`, `name`, `shortDescription` (title), `fullDescription`, `help` (remediation), `defaultConfiguration.level`, `properties.{dimension, stage, tags, precision}` |
| `results[].level` | critical, high → `error`; medium → `warning`; low, info → `note` (stage-adjusted severity) |
| `results[].locations[]` | `artifactLocation.uri` (repo-relative, URI-encoded, `uriBaseId: %SRCROOT%`); `region.startLine` / `endLine` only when known |
| `results[].partialFingerprints` | `rungFingerprint/v1` = the finding fingerprint |
| `results[].properties` | `severity`, `confidence`, `stage`, `priority`; `security-severity` for the security dimension |
| `results[].suppressions` | `[]` for reported findings; `[{kind: "external", justification}]` for baseline-suppressed ones |
| `runs[0].properties` | `classification`, `overallScore`, `repository`, `headCommit` |

`security-severity` is 9.5 / 8.0 / 5.5 / 3.0 / 1.0 for critical to info, on security rules
and results. The CLI fills `fullDescription`, `help` and tags from the rule registry;
`to_sarif(report)` without a registry falls back to the title and to the remediation of
failed rules, so stored reports can still be rendered.
