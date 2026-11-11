# Evaluation guide

The proposal evaluates rung in two phases. This page describes how to run each one with
what is in the repository. Neither phase has been run yet: the numbers in the thesis must
come from your own benchmark set and participants.

## Phase 1: diagnostic accuracy (10-15 benchmark repositories)

1. **Pick the repositories.** Aim for 10-15 open-source repositories spread across the four
   stages (at least two per stage), plus a few simulated ones you build to hit edge cases
   (for example: mature docs but no tests).
2. **Label them independently of rung.** For each repository decide the expected stage
   *before* running rung, from evidence rung does not compute: project age, release
   history, team size, adoption, and the stage descriptions in Klotins et al. Ideally a
   second rater labels them too, so you can report inter-rater agreement (Cohen's kappa).
   Labels chosen after seeing rung's output would make the accuracy figure circular.
3. **Record them** in `evaluation/benchmark.csv` (same columns as
   `evaluation/benchmark.example.csv`): `source,expected_stage,notes`.
4. **Run the harness:**

   ```bash
   python scripts/benchmark.py evaluation/benchmark.csv --out evaluation/results.csv
   ```

   It prints, per repository, expected vs. classified stage, then a confusion matrix, the
   exact accuracy and the within-one-rung accuracy. Remote repositories are cloned once into
   `.rung-cache/`.
5. **Report** exact accuracy, within-one-rung accuracy and the confusion matrix. Because
   stages are ordinal, a weighted kappa or Spearman correlation between expected and
   predicted stage order is a fairer summary than accuracy alone.
6. **Calibrate with care.** If you tune `stage_threshold` or rule stages after looking at
   results, split the set first: tune on one half, report on the other. State the commit of
   rung and of each audited repository so the study is reproducible (rung's output is
   deterministic for a given commit and config).

### Things to examine in the error analysis

- Repositories classified too low because one early rung is unmet (the ladder is gated:
  a repo with CI and Docker but no tests cannot pass stabilization). Is that the behaviour
  the model intends? `docs/scoring.md` explains the rationale.
- Rules that are `not_applicable` often (shallow clones, non-GitHub CI) and how that shifts
  fulfillment.
- Rules with low confidence that fail often: candidates for refinement.

## Phase 2: usability (8-10 developers, System Usability Scale)

1. Give each participant the same task set, for example: audit a provided repository from
   the dashboard, state its stage and why, find the top three improvements, locate one
   specific finding, then repeat one task with the CLI.
2. Record task completion and time on task, then administer the standard 10-item SUS
   questionnaire (5-point scale) plus two or three open questions about the clarity of the
   diagnosis.
3. Score SUS per participant: for odd items subtract 1 from the response, for even items
   subtract the response from 5, sum, multiply by 2.5. Report the mean, standard deviation
   and the range; 68 is the commonly used average benchmark.
4. With 8-10 participants the result is indicative, not statistically strong; say so, and
   lean on the qualitative feedback for the design iteration DSR expects.
