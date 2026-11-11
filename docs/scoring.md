# Scoring and classification

Implemented in `rung.scoring`; pure functions over rule outcomes.

## The model

1. **Outcomes.** Each rule ends as `passed`, `failed` or `not_applicable`. Not-applicable
   rules (including rules that crashed) are ignored everywhere below.
2. **Scores.** Dimension score = 100 × Σ weight(passed) / Σ weight(applicable) within the
   dimension, 100 if nothing applies. The overall score is the same ratio over all rules.
   Scores describe breadth; they do not decide the stage.
3. **Stage fulfillment.** F(s) = the same ratio over the rules whose `stage` is s; 1.0 if
   the stage has no applicable rules.
4. **The ladder.** A stage is *met* when F(s) ≥ `stage_threshold` (default 0.70, inclusive;
   a 1e-9 tolerance absorbs float noise from summed weights). The classified stage is the
   highest stage whose every predecessor is also met. Inception is the floor: a repository
   that does not meet inception is still classified `inception`, with `met: false`.
5. **Priority and stage-aware severity.** For a rule of stage R in a repository classified C:

   | Relation | Priority | Reported severity |
   | --- | --- | --- |
   | R ≤ C | `overdue` | base severity |
   | R = next(C) | `next` | base severity |
   | R beyond next(C) | `later` | `info` (`base_severity` keeps the original) |

6. **Checklist.** One item per failed rule, ordered by priority (overdue, next, later),
   then base severity (worst first), then weight (heaviest first), then rule id.

## Worked example

Ten rules of weight 1, threshold 0.70:

| Stage | Passed / applicable | F | Met |
| --- | --- | --- | --- |
| inception | 3 / 3 | 1.00 | yes |
| stabilization | 3 / 4 | 0.75 | yes |
| growth | 1 / 2 | 0.50 | no |
| maturity | 1 / 1 | 1.00 | yes |

The repository is classified **stabilization**: growth is not met, and maturity cannot be
reached by skipping it. Overall score: 8 / 10 = 80.0.

- The failed stabilization rule (say, missing lockfile, base `medium`) is **overdue** and
  stays `medium`.
- The failed growth rule (no CODEOWNERS, base `low`) is **next** and stays `low`.
- Had a maturity rule failed (unpinned actions, base `high`), it would be **later** and
  reported as `info`, with `base_severity: high`. It would not trip `--fail-on high`.

## Why not a flat score

OpenSSF Scorecard and similar tools grade every repository against one fixed checklist
and aggregate the result into a single number. That answers "how close is this to a
well-governed open-source project", and it grades a two-week-old MVP on branch protection
and signed releases. The progression model of Klotins et al. says the practices a start-up
needs depend on where it is in its life cycle, so rung:

- classifies first, and only then decides how loudly to report each gap;
- gates stages in order, so breadth in advanced practices cannot hide a missing foundation;
- keeps the original severity in `base_severity`, so nothing is hidden, only ranked.

Practices that are dangerous at any stage (committed credentials, private keys) are
assigned to inception by the rule authors and are therefore never down-ranked.

## Limits

The threshold and the rule-to-stage mapping are a first operationalisation and should be
calibrated against a labelled benchmark. A stage with very few applicable rules moves in
large steps (one rule of two is 50 points).
