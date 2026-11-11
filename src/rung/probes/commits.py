"""Commit-history probe (``Dimension.commits``, rules ``COM001``..``COM010``).

Every rule is a pure function of the snapshot's git history. Time is always measured
between commits (never against the wall clock), author identity is the lower-cased author
email, and "recent" means the newest ``RECENT_WINDOW`` commits. A rule that cannot judge -
no git repository, a shallow clone, or too little history for its statistic - returns
``Check.na`` instead of failing.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from datetime import UTC

from rung.collect import Commit, RepoSnapshot
from rung.models import Check, Confidence, Dimension, Hit, Severity, Stage
from rung.registry import rule

#: Where history findings point: the repository's git metadata.
GIT_PATH = ".git"

MIN_COMMITS = 5  # COM001: fewer commits than this is not "real use" of version control
RECENT_WINDOW = 200  # newest commits considered by the "recent" rules
MIN_SUBJECT_SAMPLE = 5  # COM002: non-merge commits needed before judging subjects
MIN_SUBJECT_LENGTH = 10  # COM002: characters
MIN_DESCRIPTIVE_SHARE = 0.70  # COM002
MAX_EXAMPLES = 5  # example commits cited by a failing rule
MIN_SPAN_DAYS = 30  # COM003: first to last commit
MIN_ACTIVE_WEEKS = 4  # COM003: distinct ISO weeks containing a commit
MIN_CONVENTION_SAMPLE = 10  # COM004
MIN_CONVENTION_SHARE = 0.60  # COM004
MIN_CONTRIBUTORS = 3  # COM005
MIN_WORKFLOW_SAMPLE = 10  # COM006: commits needed before a workflow can be visible
MIN_REVIEW_SIGNALS = 2  # COM006: one stray merge is not a workflow
MIN_BUS_FACTOR_SAMPLE = 20  # COM008
MAX_TOP_AUTHOR_SHARE = 0.75  # COM008
MIN_RELEASE_TAGS = 5  # COM009
DUMP_MIN_FILES = 500  # COM010: files touched by a single commit
DUMP_MIN_TREE_SHARE = 0.50  # COM010: ... relative to the files tracked at HEAD
DUMP_MIN_ADDED_SHARE = 0.90  # COM010: additions / changed lines (excludes reformats, moves)

_JUNK_SUBJECTS = frozenset(
    {
        "bug fix", "bug fixes", "bugfix", "bugfixes", "change", "changes", "commit",
        "fix", "fix bug", "fix bugs", "fixed", "fixed bug", "fixed bugs", "fixes",
        "final", "final commit", "minor", "minor change", "minor changes", "minor fix",
        "minor fixes", "misc", "more changes", "more fixes", "new changes", "save",
        "small change", "small changes", "small fix", "small fixes", "some changes",
        "some fixes", "stuff", "temp", "test", "testing", "tmp", "update", "updated",
        "updates", "wip", "work in progress",
    }
)  # fmt: skip
_CONVENTIONAL_RE = re.compile(
    r"^(?:build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(?:\([^()]+\))?!?: \S",
    re.IGNORECASE,
)
_TICKET_RE = re.compile(r"^\[?(?:[A-Z][A-Z0-9]+-\d+|#\d+)\]?[:\s]")
_SCOPE_RE = re.compile(r"^[A-Za-z0-9_][\w./,*-]{0,39}: \S")
_CONVENTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Conventional Commits", _CONVENTIONAL_RE),
    ("ticket-reference prefixes", _TICKET_RE),
    ("'scope: summary' prefixes", _SCOPE_RE),
)
_BOT_RE = re.compile(
    r"\[bot\]|dependabot|renovate|github-actions|greenkeeper|snyk-bot|semantic-release"
    r"|mergify|pre-commit-ci|allcontributors|imgbot",
    re.IGNORECASE,
)
_SQUASH_RE = re.compile(r"\(#\d+\)\s*$")
_PR_MERGE_RE = re.compile(
    r"^(?:Merge pull request #\d+|Merged in \S+ \(pull request #\d+\)"
    r"|Merge branch '[^']+' into |Merge branch '[^']+'$)"
)
#: ``git pull`` merges ("Merge branch 'main' of <remote>") sync branches; nobody reviewed.
_SYNC_MERGE_RE = re.compile(r"^Merge (?:branch '[^']+' of |remote-tracking branch )")
_SEMVER_TAG_RE = re.compile(
    r"^(?:[A-Za-z][\w.]*[-/@_])?v?\d+\.\d+(?:\.\d+)?(?:[-+.][0-9A-Za-z][0-9A-Za-z.+-]*)?$"
)


# ------------------------------------------------------------------------ helpers


def _unjudgeable(repo: RepoSnapshot) -> Check | None:
    """``Check.na`` when history cannot be judged at all, else ``None``."""
    if not repo.is_git:
        return Check.na("Not a git repository: no commit history to assess")
    if repo.is_shallow:
        return Check.na("Shallow clone: history is truncated, so it cannot be judged")
    if not repo.commits:
        return Check.na("The repository has no commits yet")
    return None


def _is_bot(commit: Commit) -> bool:
    return bool(_BOT_RE.search(commit.author_email) or _BOT_RE.search(commit.author_name))


def _human_commits(commits: Sequence[Commit]) -> list[Commit]:
    """Non-merge commits not authored by an automation account."""
    return [c for c in commits if not c.is_merge and not _is_bot(c)]


def _is_descriptive(subject: str) -> bool:
    text = subject.strip()
    normalized = re.sub(r"[\s.!]+$", "", text).lower()
    return len(text) >= MIN_SUBJECT_LENGTH and normalized not in _JUNK_SUBJECTS


def _short(commit: Commit) -> str:
    return commit.sha[:7]


def _pct(share: float) -> str:
    return f"{share:.0%}"


def _is_review_signal(commit: Commit) -> bool:
    subject = commit.subject
    if _SYNC_MERGE_RE.match(subject):
        return False
    return bool(commit.is_merge or _SQUASH_RE.search(subject) or _PR_MERGE_RE.match(subject))


def release_tags(repo: RepoSnapshot) -> list[str]:
    """Tags that look like versions: ``v1.2.3``, ``1.4``, ``pkg@2.0.0``, ``release-1.0``."""
    return [t for t in repo.tags if _SEMVER_TAG_RE.match(t)]


def _history_note(repo: RepoSnapshot) -> str:
    """Suffix telling the reader when only the newest part of history was analysed."""
    if repo.commit_count > len(repo.commits):
        return f" (newest {len(repo.commits)} of {repo.commit_count} commits analysed)"
    return ""


# -------------------------------------------------------------------------- rules


@rule(
    id="COM001",
    title="Version control in real use",
    dimension=Dimension.commits,
    stage=Stage.inception,
    severity=Severity.high,
    confidence=Confidence.high,
    description=(
        "Even at inception, work must be recorded in version control as a series of "
        "commits: it is the precondition for collaboration, rollback and every other "
        "history-based practice."
    ),
    remediation=(
        "Initialise git (`git init`) and commit work in small increments instead of "
        "keeping the project as a loose directory or a single snapshot commit."
    ),
    weight=2.0,
)
def version_control_in_use(repo: RepoSnapshot) -> Check:
    if not repo.is_git:
        return Check.fail("Not a git repository: no version control metadata", at=GIT_PATH)
    if repo.is_shallow:
        return Check.na("Shallow clone: history is truncated, so it cannot be judged")
    count = repo.commit_count
    if count < MIN_COMMITS:
        return Check.fail(
            f"Only {count} commit(s) in history; at least {MIN_COMMITS} show real use",
            at=GIT_PATH,
        )
    return Check.ok(f"Git repository with {count} commits", evidence=[GIT_PATH])


@rule(
    id="COM002",
    title="Descriptive commit messages",
    dimension=Dimension.commits,
    stage=Stage.stabilization,
    severity=Severity.medium,
    confidence=Confidence.medium,
    description=(
        "Once a product is released, history becomes a maintenance tool: subjects such "
        "as 'wip' or 'fix' make it impossible to trace why a change shipped."
    ),
    remediation=(
        "Write subjects that say what changed and why, e.g. 'Fix login redirect loop on "
        "expired sessions' instead of 'fix'."
    ),
)
def descriptive_subjects(repo: RepoSnapshot) -> Check:
    if na := _unjudgeable(repo):
        return na
    sample = [c for c in repo.commits[:RECENT_WINDOW] if not c.is_merge]
    if len(sample) < MIN_SUBJECT_SAMPLE:
        return Check.na(
            f"Only {len(sample)} non-merge commit(s); need {MIN_SUBJECT_SAMPLE} to judge subjects"
        )
    poor = [c for c in sample if not _is_descriptive(c.subject)]
    share = 1 - len(poor) / len(sample)
    measured = (
        f"{len(sample) - len(poor)} of the newest {len(sample)} non-merge commits "
        f"({_pct(share)}) have a descriptive subject; expected at least "
        f"{_pct(MIN_DESCRIPTIVE_SHARE)}"
    )
    if share >= MIN_DESCRIPTIVE_SHARE:
        return Check.ok(measured, evidence=[GIT_PATH])
    hits = [
        Hit(path=GIT_PATH, message=f"Commit {_short(c)} has a non-descriptive subject")
        for c in poor[:MAX_EXAMPLES]
    ]
    return Check.fail(measured, hits=hits)


@rule(
    id="COM003",
    title="Sustained development activity",
    dimension=Dimension.commits,
    stage=Stage.stabilization,
    severity=Severity.low,
    confidence=Confidence.high,
    description=(
        "A stabilising product is maintained over time. History squeezed into a few days "
        "suggests a one-off dump rather than a product being kept dependable."
    ),
    remediation=(
        "Keep committing as the product evolves; this rule passes once history spans a "
        "month with work in several separate weeks."
    ),
)
def sustained_activity(repo: RepoSnapshot) -> Check:
    if na := _unjudgeable(repo):
        return na
    if len(repo.commits) < MIN_COMMITS:
        return Check.na(f"Only {len(repo.commits)} commit(s); need {MIN_COMMITS} to judge activity")
    dates = [c.authored_at.astimezone(UTC) for c in repo.commits]
    span_days = (max(dates) - min(dates)).days
    weeks = len({tuple(d.isocalendar()[:2]) for d in dates})
    measured = (
        f"History spans {span_days} day(s) across {weeks} active week(s)"
        f"{_history_note(repo)}; expected at least {MIN_SPAN_DAYS} days and "
        f"{MIN_ACTIVE_WEEKS} weeks"
    )
    if span_days >= MIN_SPAN_DAYS and weeks >= MIN_ACTIVE_WEEKS:
        return Check.ok(measured, evidence=[GIT_PATH])
    if repo.commit_count > len(repo.commits):
        return Check.na(f"{measured}; older history was not analysed, so it cannot be judged")
    return Check.fail(measured, at=GIT_PATH)


@rule(
    id="COM004",
    title="Consistent commit convention",
    dimension=Dimension.commits,
    stage=Stage.growth,
    severity=Severity.low,
    confidence=Confidence.medium,
    description=(
        "As the team grows, a shared commit convention (Conventional Commits, ticket "
        "prefixes, 'scope: summary') keeps history scannable and enables automated "
        "changelogs and release notes."
    ),
    remediation=(
        "Agree on one convention, document it in CONTRIBUTING, and enforce it with a "
        "commit-msg hook or a CI check such as commitlint."
    ),
    weight=0.5,
)
def commit_convention(repo: RepoSnapshot) -> Check:
    if na := _unjudgeable(repo):
        return na
    sample = _human_commits(repo.commits[:RECENT_WINDOW])
    if len(sample) < MIN_CONVENTION_SAMPLE:
        return Check.na(
            f"Only {len(sample)} non-merge, non-bot commit(s); need "
            f"{MIN_CONVENTION_SAMPLE} to judge a convention"
        )
    counts = [(sum(1 for c in sample if rx.match(c.subject)), name) for name, rx in _CONVENTIONS]
    best, name = max(counts, key=lambda pair: pair[0])
    share = best / len(sample)
    measured = (
        f"{best} of the newest {len(sample)} non-merge, non-bot commits ({_pct(share)}) "
        f"follow {name}; expected at least {_pct(MIN_CONVENTION_SHARE)}"
    )
    if share >= MIN_CONVENTION_SHARE:
        return Check.ok(measured, evidence=[GIT_PATH])
    return Check.fail(measured, at=GIT_PATH)


@rule(
    id="COM005",
    title="Multiple contributors",
    dimension=Dimension.commits,
    stage=Stage.growth,
    severity=Severity.medium,
    confidence=Confidence.high,
    description=(
        "Growth means the team scales. A history written by one or two people shows the "
        "project still depends on its founders."
    ),
    remediation=(
        "Onboard further contributors and make sure they commit under their own identity "
        "(not a shared account)."
    ),
)
def multiple_contributors(repo: RepoSnapshot) -> Check:
    if na := _unjudgeable(repo):
        return na
    authors = {c.author_email.lower() for c in repo.commits if not _is_bot(c)}
    measured = (
        f"{len(authors)} distinct human author(s) by email{_history_note(repo)}; "
        f"expected at least {MIN_CONTRIBUTORS}"
    )
    if len(authors) >= MIN_CONTRIBUTORS:
        return Check.ok(measured, evidence=[GIT_PATH])
    return Check.fail(measured, at=GIT_PATH)


@rule(
    id="COM006",
    title="Review-based workflow",
    dimension=Dimension.commits,
    stage=Stage.growth,
    severity=Severity.medium,
    confidence=Confidence.medium,
    description=(
        "With several contributors, changes should land through pull/merge requests so "
        "that they are reviewed and tested before reaching the main branch."
    ),
    remediation=(
        "Protect the default branch and merge work through pull requests (merge or "
        "squash) instead of pushing directly."
    ),
)
def review_workflow(repo: RepoSnapshot) -> Check:
    if na := _unjudgeable(repo):
        return na
    sample = repo.commits[:RECENT_WINDOW]
    if len(sample) < MIN_WORKFLOW_SAMPLE:
        return Check.na(
            f"Only {len(sample)} commit(s); need {MIN_WORKFLOW_SAMPLE} to judge the workflow"
        )
    signals = sum(1 for c in sample if _is_review_signal(c))
    measured = (
        f"{signals} of the newest {len(sample)} commits are pull/merge-request merges or "
        f"squash merges; expected at least {MIN_REVIEW_SIGNALS}"
    )
    if signals >= MIN_REVIEW_SIGNALS:
        return Check.ok(measured, evidence=[GIT_PATH])
    return Check.fail(measured, at=GIT_PATH)


@rule(
    id="COM007",
    title="Releases are tagged",
    dimension=Dimension.commits,
    stage=Stage.growth,
    severity=Severity.medium,
    confidence=Confidence.high,
    description=(
        "A growing customer base needs identifiable versions: release tags tie what "
        "customers run to an exact commit for support, rollback and changelogs."
    ),
    remediation="Tag each release with a version, e.g. `git tag v1.0.0 && git push --tags`.",
)
def release_tags_exist(repo: RepoSnapshot) -> Check:
    if na := _unjudgeable(repo):
        return na
    tags = release_tags(repo)
    if tags:
        return Check.ok(f"{len(tags)} version tag(s) found, e.g. {tags[-1]}", evidence=[GIT_PATH])
    return Check.fail(
        f"No version tags among {len(repo.tags)} tag(s); expected names like v1.2.3",
        at=GIT_PATH,
    )


@rule(
    id="COM008",
    title="No single-author dependency (bus factor)",
    dimension=Dimension.commits,
    stage=Stage.maturity,
    severity=Severity.medium,
    confidence=Confidence.medium,
    description=(
        "An established product must survive any one person leaving. When one author "
        "writes almost every recent commit, knowledge and control are concentrated."
    ),
    remediation=(
        "Spread ownership: rotate areas of the codebase, require reviews by a second "
        "maintainer and document subsystems that only one person understands."
    ),
)
def bus_factor(repo: RepoSnapshot) -> Check:
    if na := _unjudgeable(repo):
        return na
    sample = _human_commits(repo.commits)[:RECENT_WINDOW]
    if len(sample) < MIN_BUS_FACTOR_SAMPLE:
        return Check.na(
            f"Only {len(sample)} non-merge, non-bot commit(s); need "
            f"{MIN_BUS_FACTOR_SAMPLE} to judge author concentration"
        )
    by_author = Counter(c.author_email.lower() for c in sample)
    top = max(by_author.values())
    share = top / len(sample)
    measured = (
        f"The most active author wrote {top} of the newest {len(sample)} non-merge, "
        f"non-bot commits ({_pct(share)}) among {len(by_author)} author(s); expected at "
        f"most {_pct(MAX_TOP_AUTHOR_SHARE)}"
    )
    if share <= MAX_TOP_AUTHOR_SHARE:
        return Check.ok(measured, evidence=[GIT_PATH])
    return Check.fail(measured, at=GIT_PATH)


@rule(
    id="COM009",
    title="Established release history",
    dimension=Dimension.commits,
    stage=Stage.maturity,
    severity=Severity.low,
    confidence=Confidence.high,
    description=(
        "A mature product ships repeatedly. A series of version tags is the evidence of a "
        "sustained, repeatable release process."
    ),
    remediation=(
        "Release regularly and tag every release; automate tagging in the release "
        "pipeline so no version is skipped."
    ),
)
def release_history(repo: RepoSnapshot) -> Check:
    if na := _unjudgeable(repo):
        return na
    count = len(release_tags(repo))
    measured = f"{count} version tag(s); expected at least {MIN_RELEASE_TAGS}"
    if count >= MIN_RELEASE_TAGS:
        return Check.ok(measured, evidence=[GIT_PATH])
    return Check.fail(measured, at=GIT_PATH)


@rule(
    id="COM010",
    title="No code-dump commits",
    dimension=Dimension.commits,
    stage=Stage.stabilization,
    severity=Severity.low,
    confidence=Confidence.medium,
    description=(
        "When most of the codebase arrives in one huge commit after the first, the "
        "history cannot explain or bisect it: the code was developed elsewhere and "
        "dumped."
    ),
    remediation=(
        "Commit work incrementally in the repository itself; when importing existing "
        "code, preserve its history (e.g. `git subtree add`) instead of pasting a snapshot."
    ),
    weight=0.5,
)
def no_code_dumps(repo: RepoSnapshot) -> Check:
    if na := _unjudgeable(repo):
        return na
    tracked = len(repo.files)
    dumps = [
        c
        for c in repo.commits
        if len(c.parents) == 1
        and len(c.files) > DUMP_MIN_FILES
        and len(c.files) >= DUMP_MIN_TREE_SHARE * tracked
        and c.insertions >= DUMP_MIN_ADDED_SHARE * (c.insertions + c.deletions) > 0
    ]
    criteria = (
        f"more than {DUMP_MIN_FILES} files, at least {_pct(DUMP_MIN_TREE_SHARE)} of the "
        f"{tracked} tracked files, at least {_pct(DUMP_MIN_ADDED_SHARE)} additions"
    )
    if not dumps:
        return Check.ok(
            f"No bulk-import commit after the first among {len(repo.commits)} commits "
            f"analysed ({criteria})",
            evidence=[GIT_PATH],
        )
    hits = [
        Hit(
            path=GIT_PATH,
            message=f"Commit {_short(c)} adds {len(c.files)} files in one change",
        )
        for c in dumps[:MAX_EXAMPLES]
    ]
    return Check.fail(f"{len(dumps)} bulk-import commit(s) after the first ({criteria})", hits=hits)
