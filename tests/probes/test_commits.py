"""Commit-history probe: one true-positive and one false-positive test per rule."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from rung.collect import RepoSnapshot
from rung.models import Confidence, Dimension, Outcome, Severity, Stage
from rung.probes import commits
from rung.registry import REGISTRY
from tests.conftest import _git, commit

START = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)
ALICE = ("Alice", "alice@example.com")
BOB = ("Bob", "bob@example.com")
CAROL = ("Carol", "carol@example.com")
BOT = ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com")


def day(offset: int) -> str:
    return (START + timedelta(days=offset)).isoformat()


def history(
    subjects: list[str],
    *,
    step_days: int = 1,
    authors: list[tuple[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Commit specs for ``make_repo(commits=...)``: one per subject, ``step_days`` apart."""
    authors = authors or [ALICE]
    return [
        {
            "message": subject,
            "files": {f"src/f{i}.txt": f"{i}\n"},
            "date": day((i + 1) * step_days),
            "author": authors[i % len(authors)],
        }
        for i, subject in enumerate(subjects)
    ]


def merge_branch(root: Path, message: str, *, date: str) -> None:
    """Create a real two-parent merge commit on the current branch."""
    env = {
        "GIT_AUTHOR_NAME": ALICE[0],
        "GIT_AUTHOR_EMAIL": ALICE[1],
        "GIT_COMMITTER_NAME": ALICE[0],
        "GIT_COMMITTER_EMAIL": ALICE[1],
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
    }
    _git(root, "checkout", "-q", "-b", "topic")
    commit(root, "feat: work on a topic branch", {f"topic-{date}.txt": "x\n"}, date=date)
    _git(root, "checkout", "-q", "main")
    _git(root, "merge", "-q", "--no-ff", "-m", message, "topic", env=env)
    _git(root, "branch", "-q", "-D", "topic")


GOOD_SUBJECTS = [
    "feat: add user registration endpoint",
    "fix: handle expired session tokens",
    "docs: describe the deployment process",
    "test: cover the password reset flow",
    "refactor: split the billing module",
    "feat: add rate limiting middleware",
    "fix: correct pagination off-by-one",
    "chore: upgrade the http client",
    "feat: export audit log as csv",
    "fix: retry failed webhook deliveries",
    "perf: cache the permission lookups",
    "feat: add organisation invitations",
]


# ------------------------------------------------------------------- registration


def test_registered_rules_are_well_formed():
    rules = [r for r in REGISTRY if r.id.startswith("COM")]
    assert [r.id for r in rules] == [f"COM{n:03d}" for n in range(1, 11)]
    assert len({r.run for r in rules}) == len(rules)
    for r in rules:
        assert r.dimension is Dimension.commits
        assert r.title and r.description.strip() and r.remediation.strip()
        assert r.run.__module__ == commits.__name__
    by_id = {r.id: r for r in rules}
    assert by_id["COM001"].stage is Stage.inception
    assert by_id["COM004"].severity is Severity.low
    assert by_id["COM004"].confidence is Confidence.medium
    assert by_id["COM006"].confidence is Confidence.medium
    assert by_id["COM008"].stage is Stage.maturity
    assert (by_id["COM010"].severity, by_id["COM010"].confidence) == (
        Severity.low,
        Confidence.medium,
    )


ALL_RULES = [
    commits.version_control_in_use,
    commits.descriptive_subjects,
    commits.sustained_activity,
    commits.commit_convention,
    commits.multiple_contributors,
    commits.review_workflow,
    commits.release_tags_exist,
    commits.bus_factor,
    commits.release_history,
    commits.no_code_dumps,
]


@pytest.mark.parametrize("rule_fn", ALL_RULES)
def test_shallow_clone_is_never_judged(make_repo, tmp_path, rule_fn):
    origin = make_repo({"a.txt": "1\n"}, commits=history(["wip", "wip", "wip"]))
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", origin.root.as_uri(), str(shallow)],
        check=True,
        capture_output=True,
    )
    repo = RepoSnapshot(shallow)
    assert repo.is_shallow
    assert rule_fn(repo).outcome is Outcome.not_applicable


@pytest.mark.parametrize("rule_fn", ALL_RULES[1:])
def test_plain_directory_only_fails_com001(make_repo, rule_fn):
    repo = make_repo({"main.py": "print('hi')\n"}, git=False)
    assert rule_fn(repo).outcome is Outcome.not_applicable


def test_rules_are_deterministic(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(["wip", "fix", *GOOD_SUBJECTS]))
    again = RepoSnapshot(repo.root)
    assert [fn(repo) for fn in ALL_RULES] == [fn(again) for fn in ALL_RULES]


# ------------------------------------------------------------------------- COM001


def test_com001_fails_without_git(make_repo):
    check = commits.version_control_in_use(make_repo({"main.py": "x\n"}, git=False))
    assert check.outcome is Outcome.failed
    assert check.hits[0].path == ".git"


def test_com001_fails_on_a_single_snapshot_commit(make_repo):
    check = commits.version_control_in_use(make_repo({"main.py": "x\n"}))
    assert check.outcome is Outcome.failed
    assert "Only 1 commit" in check.summary


def test_com001_passes_at_the_threshold(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(["wip"] * 4))
    check = commits.version_control_in_use(repo)
    assert check.outcome is Outcome.passed
    assert "5 commits" in check.summary


# ------------------------------------------------------------------------- COM002


def test_com002_fails_on_junk_subjects_and_cites_short_shas(make_repo):
    subjects = ["wip", "fix", "update", ".", "Fixed bugs.", "stuff", "add the login page"]
    repo = make_repo({"a.txt": "1\n"}, commits=history(subjects))
    check = commits.descriptive_subjects(repo)
    assert check.outcome is Outcome.failed
    assert "2 of the newest 8" in check.summary
    assert 1 <= len(check.hits) <= commits.MAX_EXAMPLES
    shas = {c.sha[:7] for c in repo.commits}
    for hit in check.hits:
        assert hit.path == ".git"
        assert any(sha in hit.message for sha in shas)


def test_com002_tolerates_a_few_terse_subjects(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(["wip", "fix", *GOOD_SUBJECTS[:8]]))
    check = commits.descriptive_subjects(repo)
    assert check.outcome is Outcome.passed
    assert "9 of the newest 11" in check.summary


def test_com002_ignores_merge_commit_subjects(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(GOOD_SUBJECTS[:6]))
    for i in range(4):
        merge_branch(repo.root, "Merge", date=day(20 + i))
    check = commits.descriptive_subjects(RepoSnapshot(repo.root))
    assert check.outcome is Outcome.passed


def test_com002_not_applicable_with_too_little_history(make_repo):
    repo = make_repo({"a.txt": "1\n"}, message="wip", commits=history(["wip"]))
    assert commits.descriptive_subjects(repo).outcome is Outcome.not_applicable


# ------------------------------------------------------------------------- COM003


def test_com003_fails_when_history_is_a_weekend_burst(make_repo):
    specs = history(GOOD_SUBJECTS)
    for i, spec in enumerate(specs):
        spec["date"] = (START + timedelta(hours=i + 1)).isoformat()
    check = commits.sustained_activity(make_repo({"a.txt": "1\n"}, date=day(0), commits=specs))
    assert check.outcome is Outcome.failed
    assert "spans 0 day(s) across 1 active week(s)" in check.summary


def test_com003_passes_on_old_but_sustained_history(make_repo):
    # Measured between commits: a project last touched long ago is still "sustained".
    repo = make_repo({"a.txt": "1\n"}, date=day(0), commits=history(GOOD_SUBJECTS[:6], step_days=8))
    check = commits.sustained_activity(repo)
    assert check.outcome is Outcome.passed
    assert "spans 48 day(s)" in check.summary


def test_com003_fails_on_a_long_span_with_few_active_weeks(make_repo):
    specs = history(GOOD_SUBJECTS[:5])
    specs[-1]["date"] = day(90)
    check = commits.sustained_activity(make_repo({"a.txt": "1\n"}, date=day(0), commits=specs))
    assert check.outcome is Outcome.failed
    assert "spans 90 day(s) across 2 active week(s)" in check.summary


def test_com003_not_applicable_with_too_little_history(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(["wip"]))
    assert commits.sustained_activity(repo).outcome is Outcome.not_applicable


# ------------------------------------------------------------------------- COM004


def test_com004_fails_on_free_form_subjects(make_repo):
    subjects = [f"Implemented part {i} of the importer" for i in range(11)]
    check = commits.commit_convention(make_repo({"a.txt": "1\n"}, commits=history(subjects)))
    assert check.outcome is Outcome.failed
    assert "expected at least 60%" in check.summary


def test_com004_passes_on_conventional_commits(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(GOOD_SUBJECTS))
    check = commits.commit_convention(repo)
    assert check.outcome is Outcome.passed
    assert "Conventional Commits" in check.summary


def test_com004_accepts_ticket_prefixes_and_ignores_bot_commits(make_repo):
    subjects = [f"RUNG-{i} Tighten the stage classifier" for i in range(10)]
    specs = history(subjects)
    specs += [
        {"message": f"Bump dep{i} from 1.0 to 1.{i}", "date": day(40 + i), "author": BOT}
        for i in range(10)
    ]
    check = commits.commit_convention(make_repo({"a.txt": "1\n"}, message="init", commits=specs))
    assert check.outcome is Outcome.passed
    assert "ticket-reference prefixes" in check.summary


def test_com004_not_applicable_with_too_little_history(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(["no convention here"] * 3))
    assert commits.commit_convention(repo).outcome is Outcome.not_applicable


# ------------------------------------------------------------------------- COM005


def test_com005_fails_when_one_person_uses_many_spellings_and_bots(make_repo):
    # The fixture's root commit adds one more human (dev@example.com).
    authors = [ALICE, ("alice", "Alice@Example.com"), BOT, ("renovate", "bot@renovate.io")]
    repo = make_repo({"a.txt": "1\n"}, commits=history(GOOD_SUBJECTS[:10], authors=authors))
    check = commits.multiple_contributors(repo)
    assert check.outcome is Outcome.failed
    assert "2 distinct human author(s)" in check.summary


def test_com005_passes_with_three_humans(make_repo):
    repo = make_repo(
        {"a.txt": "1\n"}, commits=history(GOOD_SUBJECTS[:6], authors=[ALICE, BOB, CAROL])
    )
    check = commits.multiple_contributors(repo)
    assert check.outcome is Outcome.passed
    assert "4 distinct human author(s)" in check.summary  # + the fixture's default author


# ------------------------------------------------------------------------- COM006


def test_com006_fails_on_linear_direct_pushes(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(GOOD_SUBJECTS))
    check = commits.review_workflow(repo)
    assert check.outcome is Outcome.failed
    assert check.summary.startswith("0 of the newest 13 commits")


def test_com006_does_not_count_git_pull_merges(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(GOOD_SUBJECTS[:8]))
    for i in range(3):
        merge_branch(repo.root, "Merge branch 'main' of github.com:acme/widget", date=day(30 + i))
    assert commits.review_workflow(RepoSnapshot(repo.root)).outcome is Outcome.failed


def test_com006_passes_on_squash_merged_pull_requests(make_repo):
    # Linear history with no merge commits still shows PRs through "(#n)" suffixes.
    subjects = [*GOOD_SUBJECTS[:9], "feat: add sso login (#41)", "fix: flaky test (#42)"]
    check = commits.review_workflow(make_repo({"a.txt": "1\n"}, commits=history(subjects)))
    assert check.outcome is Outcome.passed
    assert check.summary.startswith("2 of the newest 12 commits")


def test_com006_passes_on_merge_commits(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(GOOD_SUBJECTS[:6]))
    merge_branch(repo.root, "Merge pull request #7 from acme/topic", date=day(30))
    merge_branch(repo.root, "Merge branch 'topic' into 'main'", date=day(31))
    assert commits.review_workflow(RepoSnapshot(repo.root)).outcome is Outcome.passed


def test_com006_not_applicable_with_too_little_history(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(GOOD_SUBJECTS[:3]))
    assert commits.review_workflow(repo).outcome is Outcome.not_applicable


# ------------------------------------------------------------- COM007 and COM009


def test_com007_fails_without_version_tags(make_repo):
    specs = history(GOOD_SUBJECTS[:3])
    specs[0]["tag"] = "before-refactor"
    specs[1]["tag"] = "demo-day"
    check = commits.release_tags_exist(make_repo({"a.txt": "1\n"}, commits=specs))
    assert check.outcome is Outcome.failed
    assert "among 2 tag(s)" in check.summary


@pytest.mark.parametrize("tag", ["v1.2.3", "0.4", "2.0.0-rc.1", "api/v1.0.0", "release-1.0"])
def test_com007_accepts_common_version_tag_styles(make_repo, tag):
    specs = history(GOOD_SUBJECTS[:2])
    specs[1]["tag"] = tag
    check = commits.release_tags_exist(make_repo({"a.txt": "1\n"}, commits=specs))
    assert check.outcome is Outcome.passed
    assert tag in check.summary


def test_com009_fails_with_too_few_releases(make_repo):
    specs = history(GOOD_SUBJECTS[:6])
    for spec, tag in zip(specs, ["v0.1.0", "v0.2.0", "nightly", "wip-tag"], strict=False):
        spec["tag"] = tag
    check = commits.release_history(make_repo({"a.txt": "1\n"}, commits=specs))
    assert check.outcome is Outcome.failed
    assert check.summary.startswith("2 version tag(s)")


def test_com009_passes_with_five_releases_in_mixed_styles(make_repo):
    specs = history(GOOD_SUBJECTS[:6])
    for spec, tag in zip(
        specs, ["0.1", "v0.2.0", "v1.0.0-beta.1", "v1.0.0", "v1.1.0"], strict=False
    ):
        spec["tag"] = tag
    check = commits.release_history(make_repo({"a.txt": "1\n"}, commits=specs))
    assert check.outcome is Outcome.passed
    assert check.summary.startswith("5 version tag(s)")


# ------------------------------------------------------------------------- COM008


def test_com008_fails_when_one_author_dominates(make_repo):
    authors = [ALICE] * 9 + [BOB]
    repo = make_repo(
        {"a.txt": "1\n"},
        commits=history([f"feat: add feature number {i}" for i in range(20)], authors=authors),
    )
    check = commits.bus_factor(repo)
    assert check.outcome is Outcome.failed
    assert "18 of the newest 21" in check.summary and "86%" in check.summary


def test_com008_ignores_bot_commits_when_measuring_concentration(make_repo):
    # A bot writing most commits must neither count as the top author nor dilute the humans.
    authors = [ALICE, BOB, BOT, BOT, BOT, BOT]
    repo = make_repo(
        {"a.txt": "1\n"},
        commits=history([f"feat: add feature number {i}" for i in range(60)], authors=authors),
    )
    check = commits.bus_factor(repo)
    assert check.outcome is Outcome.passed
    assert "10 of the newest 21" in check.summary


def test_com008_not_applicable_for_a_young_single_author_repo(make_repo):
    repo = make_repo({"a.txt": "1\n"}, commits=history(GOOD_SUBJECTS))
    assert commits.bus_factor(repo).outcome is Outcome.not_applicable


# ------------------------------------------------------------------------- COM010


def bulk(count: int, prefix: str = "vendor") -> dict[str, str]:
    return {f"{prefix}/f{i:04d}.txt": f"{i}\n" for i in range(count)}


def test_com010_fails_when_the_codebase_arrives_in_one_later_commit(make_repo):
    repo = make_repo(
        {"README.md": "# x\n"},
        commits=[{"message": "add project", "files": bulk(commits.DUMP_MIN_FILES + 1)}],
    )
    check = commits.no_code_dumps(repo)
    assert check.outcome is Outcome.failed
    assert check.hits[0].path == ".git"
    assert repo.commits[0].sha[:7] in check.hits[0].message
    assert "adds 501 files" in check.hits[0].message


def test_com010_skips_the_root_commit(make_repo):
    repo = make_repo(bulk(commits.DUMP_MIN_FILES + 1), commits=history(GOOD_SUBJECTS[:2]))
    assert commits.no_code_dumps(repo).outcome is Outcome.passed


def test_com010_ignores_a_mass_reformat(make_repo):
    # Touches every file, but rewrites lines instead of adding a codebase.
    files = bulk(commits.DUMP_MIN_FILES + 1)
    repo = make_repo(
        files,
        commits=[{"message": "style: reformat everything", "files": {p: "x\n" for p in files}}],
    )
    assert len(repo.commits[0].files) > commits.DUMP_MIN_FILES
    assert commits.no_code_dumps(repo).outcome is Outcome.passed


def test_com010_ignores_a_large_addition_to_a_much_larger_repo(make_repo):
    repo = make_repo(
        bulk(1200, "src"),
        commits=[{"message": "feat: add locale data", "files": bulk(501, "locales")}],
    )
    assert commits.no_code_dumps(repo).outcome is Outcome.passed
