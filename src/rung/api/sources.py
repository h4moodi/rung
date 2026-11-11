"""Turn an attacker-controlled ``source`` string into a local directory to audit.

Two kinds of source exist: an ``https://host/owner/repo`` URL on an allowlisted host, which
is cloned into a throwaway directory, and (only when a local root is configured) a path
inside that root. Error messages never echo the input, credentials or server paths.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_SCP_RE = re.compile(r"^[\w.-]+@[\w.-]+:")
_REMOTE_RE = re.compile(
    r"https://(?P<host>[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)"
    r"/(?P<owner>[A-Za-z0-9_][A-Za-z0-9._-]*)"
    r"/(?P<repo>[A-Za-z0-9._][A-Za-z0-9._-]*?)(?:\.git)?/?"
)

#: Options that make an untrusted clone inert: no exotic transports, no hooks, no stored
#: credentials (the API is unauthenticated), no cross-host redirects, no submodules.
_GIT_CLONE_CONFIG = (
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.file.allow=never",
    "-c", "core.hooksPath=/dev/null",
    "-c", "credential.helper=",
    "-c", "http.followRedirects=false",
    "-c", "submodule.recurse=false",
)  # fmt: skip

Runner = Callable[..., "subprocess.CompletedProcess[bytes]"]


class SourceError(Exception):
    """A rejected or failed source; ``message`` is safe to return to the client."""

    status_code = 400
    code = "invalid_source"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class SourceNotAllowed(SourceError):
    status_code = 403
    code = "source_not_allowed"


class RepoTooLarge(SourceError):
    status_code = 413
    code = "repo_too_large"


class CloneFailed(SourceError):
    status_code = 502
    code = "clone_failed"


class CloneTimeout(SourceError):
    status_code = 504
    code = "clone_timeout"


@dataclass(frozen=True)
class SourcePolicy:
    allowed_hosts: tuple[str, ...]
    local_root: Path | None = None
    clone_timeout: int = 120
    max_repo_bytes: int = 500 * 1024 * 1024


@dataclass(frozen=True)
class ResolvedSource:
    """A validated source. ``display`` is what is stored and shown; ``url`` xor ``path``."""

    display: str
    url: str | None = None
    path: Path | None = None


def resolve_source(source: str, policy: SourcePolicy) -> ResolvedSource:
    """Validate ``source`` against ``policy`` without touching the network."""
    source = source.strip()
    if not source or "\x00" in source or source.startswith("-"):
        raise SourceError("source must be an https repository URL or an allowed local path")
    if _SCHEME_RE.match(source):
        return _resolve_remote(source, policy)
    if _SCP_RE.match(source):
        raise SourceError("only https:// repository URLs are supported")
    return _resolve_local(source, policy)


def _resolve_remote(source: str, policy: SourcePolicy) -> ResolvedSource:
    if not source.lower().startswith("https://"):
        raise SourceError("only https:// repository URLs are supported")
    if "@" in source:
        raise SourceError("repository URLs must not contain credentials")
    m = _REMOTE_RE.fullmatch(source[:8].lower() + source[8:])
    if m is None:
        m_host = re.match(r"https://([^/?#]+)", source, re.IGNORECASE)
        if m_host is None or not re.fullmatch(r"[A-Za-z0-9.-]+", m_host.group(1)):
            raise SourceError("repository URL must look like https://host/owner/repo")
        m = _REMOTE_RE.fullmatch(f"https://{m_host.group(1).lower()}{source[m_host.end() :]}")
    if m is None or {m["owner"], m["repo"]} & {".", ".."}:
        raise SourceError("repository URL must look like https://host/owner/repo")
    if m["host"] not in policy.allowed_hosts:
        raise SourceNotAllowed("repository host is not in the allowlist")
    url = f"https://{m['host']}/{m['owner']}/{m['repo']}"
    return ResolvedSource(display=url, url=url)


def _resolve_local(source: str, policy: SourcePolicy) -> ResolvedSource:
    if policy.local_root is None:
        raise SourceNotAllowed("local paths are disabled on this server")
    root = policy.local_root.resolve()
    try:
        target = (root / source).resolve()
    except (OSError, ValueError) as exc:
        raise SourceError("local path is not valid") from exc
    if not target.is_relative_to(root):
        raise SourceNotAllowed("local path is outside the allowed root")
    if not target.is_dir():
        raise SourceError("local path is not a directory")
    return ResolvedSource(display=target.relative_to(root).as_posix(), path=target)


def clone_command(url: str, dest: Path) -> list[str]:
    """Full-history, single-branch clone; ``--`` stops the URL being read as an option."""
    return [
        "git", *_GIT_CLONE_CONFIG, "clone", "--quiet", "--single-branch",
        "--no-recurse-submodules", "--", url, str(dest),
    ]  # fmt: skip


def directory_size(path: Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path, followlinks=False):
        for name in filenames:
            total += os.lstat(os.path.join(dirpath, name)).st_size
    return total


@contextmanager
def checkout(
    resolved: ResolvedSource, policy: SourcePolicy, *, runner: Runner = subprocess.run
) -> Iterator[Path]:
    """Yield a directory to audit; a cloned remote is deleted again on exit."""
    if resolved.path is not None:
        yield resolved.path
        return
    if resolved.url is None:
        raise SourceError("source must be an https repository URL or an allowed local path")
    workdir = Path(tempfile.mkdtemp(prefix="rung-clone-"))
    try:
        dest = workdir / "repo"
        _clone(clone_command(resolved.url, dest), policy.clone_timeout, runner)
        if directory_size(dest) > policy.max_repo_bytes:
            raise RepoTooLarge("repository exceeds the configured size limit")
        yield dest
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _clone(command: Sequence[str], timeout: int, runner: Runner) -> None:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": ""}
    try:
        result = runner(
            list(command), env=env, timeout=timeout, capture_output=True, check=False,
            stdin=subprocess.DEVNULL,
        )  # fmt: skip
    except subprocess.TimeoutExpired as exc:
        raise CloneTimeout("cloning the repository timed out") from exc
    except OSError as exc:
        raise CloneFailed("git is not available on the server") from exc
    if result.returncode != 0:
        raise CloneFailed("could not clone the repository (it may be private or not exist)")
