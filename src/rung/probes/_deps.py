"""Dependency-manifest helpers shared by the security rules (not a probe module)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from rung.collect import RepoSnapshot
from rung.models import Confidence
from rung.probes._secrets import is_low_trust_path

_MANIFEST_NAMES = frozenset(
    {
        "pyproject.toml", "pipfile", "setup.py", "setup.cfg", "package.json", "go.mod",
        "cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts", "gemfile",
        "composer.json", "mix.exs", "environment.yml", "pubspec.yaml", "package.swift",
        "build.sbt",
    }
)  # fmt: skip
_MANIFEST_SUFFIXES = (".csproj", ".fsproj", ".vbproj", ".gemspec")
_REQUIREMENTS_RE = re.compile(r"^requirements[\w.\-]*\.txt$")
_VENDORED_PARTS = frozenset(
    {"node_modules", "vendor", "third_party", "third-party", "site-packages", "bower_components"}
)
#: Languages that have a standard dependency manifest (C/C++ and shell deliberately absent).
_SOURCE_SUFFIXES = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".kt",
    ".rb", ".php", ".cs", ".fs", ".ex", ".exs", ".swift", ".scala", ".dart",
)  # fmt: skip
_JS_LOCKS = (
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "bun.lockb",
)  # fmt: skip
_PY_LOCKS = ("poetry.lock", "pdm.lock", "uv.lock", "Pipfile.lock")
_PY_LOCKED_TOOLS_RE = re.compile(r"^\[tool\.(?:poetry|pdm|uv)\b", re.MULTILINE)
_GO_REQUIRE_RE = re.compile(r"^\s*require\b", re.MULTILINE)
_CARGO_DEPS_RE = re.compile(r"^\[(?:workspace\.)?(?:dev-|build-)?dependencies", re.MULTILINE)
_REQ_UNPINNED_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]*(?:\[[^\]]*\])?$")
_REQ_PINNED_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]*(?:\[[^\]]*\])?\s*===?\s*[^\s*,]+$")
_JS_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
_JS_UNPINNED = frozenset({"", "*", "latest", "x"})


def _vendored(path: str) -> bool:
    return any(p in _VENDORED_PARTS for p in PurePosixPath(path.lower()).parts[:-1])


def find_manifests(repo: RepoSnapshot) -> list[str]:
    out = []
    for path in repo.files:
        name = PurePosixPath(path).name.lower()
        if _vendored(path):
            continue
        if (
            name in _MANIFEST_NAMES
            or name.endswith(_MANIFEST_SUFFIXES)
            or _REQUIREMENTS_RE.match(name)
        ):
            out.append(path)
    return out


def source_files(repo: RepoSnapshot) -> list[str]:
    return [f for f in repo.files if f.lower().endswith(_SOURCE_SUFFIXES) and not _vendored(f)]


@dataclass(frozen=True)
class Requirement:
    line: int
    name: str
    pinned: bool
    has_specifier: bool


def parse_requirements(lines: list[str]) -> list[Requirement]:
    """Named entries of a requirements file; options, URLs and local paths are skipped."""
    out = []
    for no, raw in enumerate(lines, start=1):
        text = raw.split(" #", 1)[0].strip().rstrip("\\").strip()
        if not text or text.startswith(("#", "-", ".", "/")) or "://" in text or " @ " in text:
            continue
        spec = text.split(";", 1)[0].split("--hash", 1)[0].strip()
        name = re.match(r"[A-Za-z0-9][A-Za-z0-9._\-]*", spec)
        if name is None:
            continue
        out.append(
            Requirement(
                line=no,
                name=name.group(0),
                pinned=bool(_REQ_PINNED_RE.match(spec)),
                has_specifier=not _REQ_UNPINNED_RE.match(spec),
            )
        )
    return out


def package_json_deps(repo: RepoSnapshot, path: str) -> dict[str, str]:
    """``{name: version spec}`` over the dependency sections; {} if unparsable."""
    try:
        data = json.loads(repo.read_text(path) or "")
    except ValueError:
        return {}
    out: dict[str, str] = {}
    if isinstance(data, dict):
        for section in _JS_DEP_SECTIONS:
            deps = data.get(section)
            if isinstance(deps, dict):
                out.update({str(k): v for k, v in deps.items() if isinstance(v, str)})
    return out


def is_unpinned_js_spec(spec: str) -> bool:
    return spec.strip().lower() in _JS_UNPINNED


def _has_lock(repo: RepoSnapshot, manifest: str, names: tuple[str, ...]) -> str | None:
    """A lockfile next to the manifest or in an ancestor directory (workspace root)."""
    directory = PurePosixPath(manifest).parent
    for folder in (directory, *directory.parents):
        for name in names:
            candidate = name if folder.as_posix() == "." else f"{folder.as_posix()}/{name}"
            if repo.exists(candidate):
                return candidate
    return None


@dataclass(frozen=True)
class LockUnit:
    """One manifest that should be accompanied by a lockfile."""

    manifest: str
    expected: str
    lockfile: str | None
    confidence: Confidence


def lock_units(repo: RepoSnapshot) -> list[LockUnit]:
    units = []
    for path in find_manifests(repo):
        name = PurePosixPath(path).name
        text = repo.read_text(path) or ""
        directory = PurePosixPath(path).parent
        confidence = Confidence.low if is_low_trust_path(path) else Confidence.medium
        expected: tuple[str, ...] | None = None
        lock: str | None = None
        if name == "package.json":
            if package_json_deps(repo, path):
                expected = _JS_LOCKS
        elif name == "pyproject.toml":
            if _PY_LOCKED_TOOLS_RE.search(text):
                expected = _PY_LOCKS[:3]
        elif name == "Pipfile":
            expected = ("Pipfile.lock",)
        elif name == "requirements.txt":
            reqs = parse_requirements(text.splitlines())
            if reqs:
                expected = _PY_LOCKS
                lock = path if all(r.pinned for r in reqs) else None
        elif name == "Cargo.toml":
            if _CARGO_DEPS_RE.search(text):
                expected = ("Cargo.lock",)
                is_binary = "[[bin]]" in text or repo.exists((directory / "src/main.rs").as_posix())
                if not is_binary:
                    confidence = Confidence.low  # libraries may legitimately omit Cargo.lock
        elif name == "go.mod":
            if _GO_REQUIRE_RE.search(text):
                expected = ("go.sum",)
        elif name == "Gemfile":
            expected = ("Gemfile.lock",)
        elif name == "composer.json":
            if '"require' in text:
                expected = ("composer.lock",)
        if expected is None:
            continue
        units.append(
            LockUnit(
                path, " | ".join(expected), lock or _has_lock(repo, path, expected), confidence
            )
        )
    return units
