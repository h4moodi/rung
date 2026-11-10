"""Shared test helpers: build small, fully deterministic git repositories."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from rung.collect import RepoSnapshot

FIXTURES = Path(__file__).parent / "fixtures"
DEFAULT_DATE = "2026-01-15T12:00:00+00:00"
DEFAULT_AUTHOR = ("Test Dev", "dev@example.com")


def _git(cwd: Path, *args: str, env: Mapping[str, str] | None = None) -> None:
    base = {
        "PATH": os.environ["PATH"],
        "HOME": str(cwd),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        cwd=cwd,
        env={**base, **(env or {})},
        check=True,
        capture_output=True,
    )


def write_files(root: Path, files: Mapping[str, str | bytes | None]) -> None:
    """Write ``{relative_path: content}``; a ``None`` value deletes the file."""
    for rel, content in files.items():
        target = root / rel
        if content is None:
            target.unlink(missing_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")


def commit(
    root: Path,
    message: str,
    files: Mapping[str, str | bytes | None] | None = None,
    *,
    date: str = DEFAULT_DATE,
    author: tuple[str, str] = DEFAULT_AUTHOR,
    tag: str | None = None,
) -> None:
    """Write ``files``, stage everything and commit with a fixed author and date."""
    if files:
        write_files(root, files)
    env = {
        "GIT_AUTHOR_NAME": author[0],
        "GIT_AUTHOR_EMAIL": author[1],
        "GIT_COMMITTER_NAME": author[0],
        "GIT_COMMITTER_EMAIL": author[1],
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
    }
    _git(root, "add", "-A")
    _git(root, "commit", "--allow-empty", "-m", message, env=env)
    if tag:
        _git(root, "tag", tag)


RepoFactory = Callable[..., RepoSnapshot]


@pytest.fixture
def make_repo(tmp_path: Path) -> RepoFactory:
    """Factory for throwaway repos.

    ``make_repo({"README.md": "# hi"})``                 one commit containing those files
    ``make_repo(fixture="mature_service")``              copy of tests/fixtures/mature_service
    ``make_repo(files, commits=[{...}, ...])``           extra commits, oldest first; each is
        ``{"message": str, "files": {...}, "date": iso, "author": (name, email), "tag": str}``
    ``make_repo(files, git=False)``                      plain directory, no git history
    ``make_repo(files, ignore=["vendor/**"])``           forwarded to RepoSnapshot

    Returns a ``RepoSnapshot``; the path is ``snapshot.root``.
    """
    counter = 0

    def factory(
        files: Mapping[str, str | bytes | None] | None = None,
        *,
        fixture: str | None = None,
        commits: Sequence[Mapping[str, Any]] = (),
        git: bool = True,
        message: str = "feat: initial commit",
        date: str = DEFAULT_DATE,
        **snapshot_kwargs: Any,
    ) -> RepoSnapshot:
        nonlocal counter
        counter += 1
        root = tmp_path / f"repo{counter}"
        if fixture:
            shutil.copytree(FIXTURES / fixture, root)
        else:
            root.mkdir()
        write_files(root, files or {})
        if git:
            _git(root, "init", "-q")
            commit(root, message, date=date)
            for spec in commits:
                commit(
                    root,
                    spec.get("message", "chore: update"),
                    spec.get("files"),
                    date=spec.get("date", date),
                    author=spec.get("author", DEFAULT_AUTHOR),
                    tag=spec.get("tag"),
                )
        return RepoSnapshot(root, **snapshot_kwargs)

    return factory
