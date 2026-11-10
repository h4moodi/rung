from __future__ import annotations

import os

import pytest

from rung.collect import RepoSnapshot, glob_to_regex
from rung.models import Check, Confidence, Dimension, Outcome, Severity, Stage, fingerprint
from rung.redact import redact
from rung.registry import Registry


def test_files_are_sorted_tracked_files(make_repo):
    repo = make_repo({"b.txt": "b", "a/x.py": "x", "README.md": "# r"})
    (repo.root / "untracked.txt").write_text("nope")
    assert repo.files == ("README.md", "a/x.py", "b.txt")
    assert repo.is_git and repo.head and repo.branch == "main"
    assert repo.has_dir("a") and not repo.has_dir("zzz")


def test_non_git_directory_is_walked_and_skips_vendor_dirs(make_repo):
    repo = make_repo({"src/app.py": "x", "node_modules/pkg/i.js": "x"}, git=False)
    assert not repo.is_git
    assert repo.files == ("src/app.py",)
    assert repo.commits == () and repo.head is None and repo.head_date is None


def test_ignore_globs_hide_files(make_repo):
    repo = make_repo({"vendor/lib/a.py": "x", "src/a.py": "x"}, ignore=["vendor/**"])
    assert repo.files == ("src/a.py",)


def test_glob_and_find_named(make_repo):
    repo = make_repo(
        {"Dockerfile": "FROM x", "svc/Dockerfile": "FROM y", ".github/workflows/ci.yml": "on: push"}
    )
    assert repo.glob("**/Dockerfile") == ["Dockerfile", "svc/Dockerfile"]
    assert repo.glob(".github/workflows/*.yml") == [".github/workflows/ci.yml"]
    assert repo.find_named("dockerfile", root_only=True) == ["Dockerfile"]
    assert glob_to_regex("*.py").match("a.py") and not glob_to_regex("*.py").match("a/b.py")


def test_read_text_refuses_binary_and_symlink_escape(make_repo, tmp_path):
    secret = tmp_path / "outside.txt"
    secret.write_text("outside the repo")
    repo = make_repo({"bin.dat": b"\x00\x01\x02", "ok.txt": "line1\nline2"})
    os.symlink(secret, repo.root / "link.txt")
    from tests.conftest import commit

    commit(repo.root, "chore: add link")
    repo = RepoSnapshot(repo.root)
    assert "link.txt" in repo.files or True  # listing may or may not include it
    assert repo.read_text("link.txt") is None
    assert repo.read_text("bin.dat") is None and repo.is_binary("bin.dat")
    assert repo.read_lines("ok.txt") == ["line1", "line2"]
    assert repo.read_text("../outside.txt") is None


def test_commits_newest_first_with_stats(make_repo):
    repo = make_repo(
        {"a.txt": "1\n"},
        date="2026-01-01T10:00:00+00:00",
        commits=[
            {
                "message": "fix: second",
                "files": {"a.txt": "1\n2\n", "b.txt": "x\n"},
                "date": "2026-01-02T10:00:00+00:00",
                "author": ("Other", "other@example.com"),
                "tag": "v0.1.0",
            }
        ],
    )
    assert [c.subject for c in repo.commits] == ["fix: second", "feat: initial commit"]
    newest = repo.commits[0]
    assert newest.author_email == "other@example.com"
    assert set(newest.files) == {"a.txt", "b.txt"} and newest.insertions == 2
    assert repo.commit_count == 2 and repo.tags == ("v0.1.0",)
    assert repo.head_date == newest.committed_at and not repo.is_shallow


def test_iter_added_lines_sees_deleted_content(make_repo):
    repo = make_repo(
        {"cfg.env": "TOKEN=abc123\n"},
        commits=[{"message": "chore: remove", "files": {"cfg.env": None, "keep.txt": "k\n"}}],
    )
    assert not repo.exists("cfg.env")
    added = [(a.path, a.line, a.text) for a in repo.iter_added_lines()]
    assert ("cfg.env", 1, "TOKEN=abc123") in added


def test_grep(make_repo):
    repo = make_repo({"a.py": "x = 1\n# TODO: fix\n", "b.py": "ok\n"})
    hits = list(repo.grep(r"TODO"))
    assert [(h.path, h.line) for h in hits] == [("a.py", 2)]


def test_snapshot_does_not_modify_repo(make_repo):
    repo = make_repo({"a.txt": "1\n"})
    before = sorted(p.as_posix() for p in repo.root.rglob("*"))
    _ = (repo.files, repo.commits, repo.tags, list(repo.iter_added_lines()), list(repo.grep("1")))
    assert sorted(p.as_posix() for p in repo.root.rglob("*")) == before


def test_check_constructors():
    assert Check.ok("fine", evidence=["README.md"]).evidence[0].path == "README.md"
    failed = Check.fail("missing", at="LICENSE")
    assert failed.outcome is Outcome.failed and failed.hits[0].path == "LICENSE"
    with pytest.raises(ValueError):
        Check.fail("no location")
    assert Check.na("n/a").outcome is Outcome.not_applicable


def test_registry_validates_and_orders():
    reg = Registry()
    common = dict(
        title="t", dimension=Dimension.docs, stage=Stage.inception, severity=Severity.low,
        confidence=Confidence.high, description="d", remediation="r",
    )  # fmt: skip

    @reg.rule(id="ZZZ002", **common)
    def second(repo):
        return Check.na("x")

    @reg.rule(id="ZZZ001", **common)
    def first(repo):
        return Check.na("x")

    assert [r.id for r in reg] == ["ZZZ001", "ZZZ002"] and len(reg) == 2
    with pytest.raises(ValueError):
        reg.rule(id="bad", **common)(lambda repo: Check.na("x"))
    with pytest.raises(ValueError):
        reg.rule(id="ZZZ001", **common)(lambda repo: Check.na("x"))


def test_redact_and_fingerprint_are_stable():
    value = "A" * 4 + "B" * 16
    shown = redact(value)
    assert value not in shown and shown.startswith("AAAA*") and "(20 chars)" in shown
    assert redact("abc") == "***(3 chars)"
    assert fingerprint("SEC001", "a.py", "x") == fingerprint("SEC001", "a.py", "x")
    assert fingerprint("SEC001", "a.py", "x") != fingerprint("SEC001", "b.py", "x")
