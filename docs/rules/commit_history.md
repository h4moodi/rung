# Commit history rules (`COM0xx`)

Source: `src/rung/probes/commits.py`. All rules read git history only. They return
**n/a** (excluded from scoring) for a non-git directory (except COM001, which fails), a
shallow clone (truncated history cannot be judged), or less history than the rule's
minimum sample. Time is measured between commits, never against today's date. "Recent"
means the newest 200 commits; bots (dependabot, renovate, github-actions, `[bot]`, ...) are
ignored where authors matter. Findings point at `.git`.

**Suppressing any rule:** add its id to `rung.toml`:

```toml
[rules]
disable = ["COM004"]
```

or keep the rule on and accept one finding with a justified entry in the baseline file
(`rung baseline --output rung-baseline.json --justification "..."`).

| ID | Stage | Sev. / conf. | Detects (fails when) | Why it matters at this stage | Fix |
| --- | --- | --- | --- | --- | --- |
| COM001 | inception | high / high | Not a git repo, or fewer than 5 commits | Version control is the precondition for every other practice, even for an MVP | `git init`, commit in small increments |
| COM002 | stabilization | medium / medium | < 70% of recent non-merge subjects are descriptive (>= 10 chars and not "wip", "fix", "update", "."...); n/a below 5 commits. Cites up to 5 short SHAs | After release, history is a maintenance tool; junk subjects make changes untraceable | Write subjects that say what changed and why |
| COM003 | stabilization | low / high | History spans < 30 days or < 4 distinct ISO weeks (first to last commit); n/a below 5 commits | A product being stabilised is maintained over time, not dumped in a weekend | Keep committing as the product evolves |
| COM004 | growth | low / medium | < 60% of recent non-merge, non-bot subjects follow one convention (Conventional Commits, ticket prefix `ABC-12`/`#12`, or `scope: summary`); n/a below 10 | A growing team needs scannable history and automated changelogs | Agree on a convention; enforce with commitlint |
| COM005 | growth | medium / high | < 3 distinct human author emails (case-insensitive) | Growth means the team scales beyond the founders | Onboard contributors; no shared accounts |
| COM006 | growth | medium / medium | < 2 review signals in recent commits: merge commits, `Merge pull request #n`, squash subjects ending `(#n)`. `git pull` sync merges (`Merge branch 'x' of ...`) do not count; n/a below 10 commits | With several contributors, changes should be reviewed before reaching main | Protect main; merge through pull requests |
| COM007 | growth | medium / high | No version-like tag (`v1.2.3`, `1.4`, `pkg@2.0.0`, `release-1.0`) | Customers need identifiable versions for support and rollback | `git tag v1.0.0 && git push --tags` |
| COM008 | maturity | medium / medium | Top author wrote > 75% of the recent non-merge, non-bot commits; n/a below 20 | An established product must survive one person leaving | Spread ownership, require second reviewers |
| COM009 | maturity | low / high | Fewer than 5 version-like tags | Repeated tagged releases show a sustained release process | Tag every release; automate it |
| COM010 | stabilization | low / medium | A non-root, non-merge commit touching > 500 files that is >= 50% of the tracked files and >= 90% additions (so reformats, moves and additions to big repos are ignored) | Code developed elsewhere and pasted in cannot be explained or bisected | Commit incrementally; import with history (`git subtree add`) |

Known limits: authors are counted by email, so one person with two emails counts twice
(errs towards passing); only the newest `max_commits` (default 5000) commits are read and
the summary says so when history was capped.
