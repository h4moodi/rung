"""Collect stage: a strictly read-only view of the audited repository.

``RepoSnapshot`` is the only thing rules get to see. It never writes to the repo, never
touches the network, and refuses to read through symlinks that leave the repo root
(audited repos are untrusted input).
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from functools import cached_property
from pathlib import Path, PurePosixPath

from git import Repo
from git.exc import GitCommandError, InvalidGitRepositoryError, NoSuchPathError

#: Directories skipped when the target is *not* a git repo (git repos use the index).
SKIP_DIRS = frozenset(
    {
        ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
        ".pytest_cache", ".ruff_cache", ".next", "dist", "build", "target",
    }
)  # fmt: skip

DEFAULT_MAX_COMMITS = 5000
DEFAULT_MAX_FILE_BYTES = 1_000_000

_GIT_ENV = {
    "GIT_OPTIONAL_LOCKS": "0",  # never take index.lock / refresh the index
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
    "LC_ALL": "C",
}
# Defensive config for untrusted repos: no fsmonitor hook, no pager, no external diff.
_GIT_SAFE = ("-c", "core.fsmonitor=false", "-c", "core.pager=cat", "-c", "diff.external=")

_RS, _FS = "\x1e", "\x1f"
_LOG_FORMAT = f"{_RS}%H{_FS}%an{_FS}%ae{_FS}%aI{_FS}%cI{_FS}%P{_FS}%s"


@dataclass(frozen=True)
class Commit:
    sha: str
    author_name: str
    author_email: str
    authored_at: datetime
    committed_at: datetime
    parents: tuple[str, ...]
    subject: str
    files: tuple[str, ...]
    insertions: int
    deletions: int

    @property
    def is_merge(self) -> bool:
        return len(self.parents) > 1


@dataclass(frozen=True)
class AddedLine:
    """A line added by some commit in history (used for secrets-in-history checks)."""

    sha: str
    path: str
    line: int
    text: str


@dataclass(frozen=True)
class Match:
    path: str
    line: int
    text: str
    match: re.Match[str]


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a repo glob to a regex. ``**`` crosses directories, ``*`` does not."""
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(out) + r"\Z", re.IGNORECASE)


class RepoSnapshot:
    """Read-only access to a repository's working tree and (if present) git history.

    All paths are repo-relative POSIX strings. ``files`` is sorted, so iteration order -
    and therefore rule output - is deterministic.
    """

    def __init__(
        self,
        root: Path,
        *,
        ignore: Sequence[str] = (),
        max_commits: int = DEFAULT_MAX_COMMITS,
    ) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise NotADirectoryError(f"not a directory: {root}")
        self.max_commits = max_commits
        self._ignore = tuple(glob_to_regex(p) for p in ignore)
        self._repo: Repo | None
        try:
            repo = Repo(self.root)
            # Only treat it as a git repo if the root *is* the work tree, so that a plain
            # directory nested inside some other repository is audited on its own.
            is_root = repo.working_tree_dir is not None and (
                Path(repo.working_tree_dir).resolve() == self.root
            )
            self._repo = repo if is_root else None
        except (InvalidGitRepositoryError, NoSuchPathError):
            self._repo = None

    @classmethod
    def open(cls, path: str | os.PathLike[str], **kwargs: object) -> RepoSnapshot:
        return cls(Path(path), **kwargs)  # type: ignore[arg-type]

    # ------------------------------------------------------------------ git plumbing

    def _git(self, *args: str) -> str:
        """Run a read-only git command and return its output ('' on failure)."""
        if self._repo is None:
            return ""
        try:
            raw = self._repo.git.execute(
                ["git", *_GIT_SAFE, *args],
                env=_GIT_ENV,
                stdout_as_string=False,
                strip_newline_in_stdout=False,
            )
        except GitCommandError:
            return ""
        return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)

    @property
    def is_git(self) -> bool:
        return self._repo is not None

    @cached_property
    def head(self) -> str | None:
        return self._git("rev-parse", "--verify", "-q", "HEAD").strip() or None

    @cached_property
    def branch(self) -> str | None:
        return self._git("symbolic-ref", "--short", "-q", "HEAD").strip() or None

    @cached_property
    def is_shallow(self) -> bool:
        return self._git("rev-parse", "--is-shallow-repository").strip() == "true"

    @cached_property
    def tags(self) -> tuple[str, ...]:
        return tuple(sorted(t for t in self._git("tag", "--list").splitlines() if t))

    @cached_property
    def commit_count(self) -> int:
        """Total commits reachable from HEAD (may exceed ``len(commits)`` if capped)."""
        if self.head is None:
            return 0
        out = self._git("rev-list", "--count", "HEAD").strip()
        return int(out) if out.isdigit() else 0

    @cached_property
    def commits(self) -> tuple[Commit, ...]:
        """Commits reachable from HEAD, newest first, capped at ``max_commits``."""
        if self.head is None:
            return ()
        out = self._git(
            "log", "--no-color", "--numstat", "--no-renames", "--no-ext-diff", "--no-textconv",
            f"--max-count={self.max_commits}", f"--format={_LOG_FORMAT}", "HEAD",
        )  # fmt: skip
        commits: list[Commit] = []
        for record in out.split(_RS)[1:]:
            header, _, body = record.partition("\n")
            parts = header.split(_FS)
            if len(parts) < 7:
                continue
            sha, an, ae, ad, cd, parents, subject = parts[:7]
            files: list[str] = []
            ins = dels = 0
            for line in body.splitlines():
                cols = line.split("\t")
                if len(cols) != 3:
                    continue
                files.append(cols[2])
                ins += int(cols[0]) if cols[0].isdigit() else 0
                dels += int(cols[1]) if cols[1].isdigit() else 0
            commits.append(
                Commit(
                    sha=sha,
                    author_name=an,
                    author_email=ae,
                    authored_at=datetime.fromisoformat(ad),
                    committed_at=datetime.fromisoformat(cd),
                    parents=tuple(parents.split()),
                    subject=subject,
                    files=tuple(files),
                    insertions=ins,
                    deletions=dels,
                )
            )
        return tuple(commits)

    @property
    def head_date(self) -> datetime | None:
        """Commit date of HEAD. Use this, never wall-clock time, as "now" in rules."""
        return self.commits[0].committed_at if self.commits else None

    def iter_added_lines(
        self, max_commits: int = 500, max_line_length: int = 2000
    ) -> Iterator[AddedLine]:
        """Yield every line added in the last ``max_commits`` commits (streamed).

        Lets rules find content that was committed and later deleted. Binary diffs and
        lines longer than ``max_line_length`` are skipped.
        """
        if self._repo is None or self.head is None:
            return
        proc = self._repo.git.execute(
            [
                "git", *_GIT_SAFE, "log", "-p", "--unified=0", "--no-color", "--no-renames",
                "--no-ext-diff", "--no-textconv", f"--max-count={max_commits}",
                f"--format={_RS}%H", "HEAD",
            ],
            env=_GIT_ENV,
            as_process=True,
        )  # fmt: skip
        sha = path = ""
        line_no = 0
        try:
            for raw in proc.stdout:  # type: ignore[union-attr]
                text = raw.decode("utf-8", "replace").rstrip("\n")
                if text.startswith(_RS):
                    sha, path = text[1:].strip(), ""
                elif text.startswith("+++ "):
                    path = text[6:] if text.startswith("+++ b/") else ""
                elif text.startswith("@@"):
                    m = re.match(r"@@ -\S+ \+(\d+)", text)
                    line_no = int(m.group(1)) if m else 0
                elif text.startswith("+") and path:
                    if len(text) <= max_line_length and not self._ignored(path):
                        yield AddedLine(sha=sha, path=path, line=line_no, text=text[1:])
                    line_no += 1
        finally:
            if proc.stdout:  # type: ignore[union-attr]
                proc.stdout.close()  # type: ignore[union-attr]
            try:
                proc.wait()
            except GitCommandError:
                pass  # we may have stopped reading early; exit status is irrelevant

    # ------------------------------------------------------------------ working tree

    def _ignored(self, path: str) -> bool:
        return any(rx.match(path) for rx in self._ignore)

    @cached_property
    def files(self) -> tuple[str, ...]:
        """Sorted repo-relative paths: tracked files for git repos, else a filtered walk."""
        paths: Iterable[str]
        if self._repo is not None:
            listed = self._git("ls-files", "-z").split("\0")
            paths = (p for p in listed if p and (self.root / p).is_file())
        else:
            found: list[str] = []
            for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
                dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
                rel = Path(dirpath).relative_to(self.root)
                found.extend((rel / f).as_posix() for f in filenames)
            paths = found
        return tuple(sorted(p for p in paths if not self._ignored(p)))

    @cached_property
    def _file_set(self) -> frozenset[str]:
        return frozenset(self.files)

    @cached_property
    def dirs(self) -> frozenset[str]:
        """Every directory that contains at least one file (repo-relative, no trailing /)."""
        out: set[str] = set()
        for f in self.files:
            out.update(p.as_posix() for p in PurePosixPath(f).parents if p.as_posix() != ".")
        return frozenset(out)

    def exists(self, path: str) -> bool:
        return path in self._file_set

    def has_dir(self, path: str) -> bool:
        return path.rstrip("/") in self.dirs

    def glob(self, *patterns: str) -> list[str]:
        """Files matching any glob (case-insensitive; ``**`` crosses directories)."""
        rxs = [glob_to_regex(p) for p in patterns]
        return [f for f in self.files if any(rx.match(f) for rx in rxs)]

    def find_named(self, *names: str, root_only: bool = False) -> list[str]:
        """Files whose basename equals one of ``names`` (case-insensitive)."""
        wanted = {n.lower() for n in names}
        return [
            f
            for f in self.files
            if PurePosixPath(f).name.lower() in wanted and not (root_only and "/" in f)
        ]

    def _resolve(self, path: str) -> Path | None:
        """Absolute path for a listed file, or None if it escapes the repo root."""
        if path not in self._file_set:
            return None
        full = (self.root / path).resolve()
        return full if full.is_relative_to(self.root) and full.is_file() else None

    def size(self, path: str) -> int:
        full = self._resolve(path)
        return full.stat().st_size if full else 0

    def is_binary(self, path: str) -> bool:
        full = self._resolve(path)
        if full is None:
            return False
        with full.open("rb") as fh:
            return b"\0" in fh.read(8000)

    def read_text(self, path: str, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> str | None:
        """File contents as text, or None if missing, binary, or outside the repo.

        Reads at most ``max_bytes``; undecodable bytes are replaced.
        """
        full = self._resolve(path)
        if full is None:
            return None
        with full.open("rb") as fh:
            data = fh.read(max_bytes)
        if b"\0" in data[:8000]:
            return None
        return data.decode("utf-8", "replace")

    def read_lines(self, path: str, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> list[str]:
        text = self.read_text(path, max_bytes)
        return text.splitlines() if text is not None else []

    def grep(
        self,
        pattern: str | re.Pattern[str],
        paths: Iterable[str] | None = None,
        max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> Iterator[Match]:
        """Regex-search text files line by line. ``paths`` defaults to all files."""
        rx = re.compile(pattern) if isinstance(pattern, str) else pattern
        for path in self.files if paths is None else paths:
            for no, line in enumerate(self.read_lines(path, max_bytes), start=1):
                m = rx.search(line)
                if m:
                    yield Match(path=path, line=no, text=line, match=m)
