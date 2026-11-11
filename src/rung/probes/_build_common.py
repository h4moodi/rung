"""Helpers shared by the containers, testing and CI/CD probes (not a probe itself)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

import yaml

from rung.collect import RepoSnapshot

#: Directories whose contents are third-party, generated or test data, never judged.
VENDORED_DIRS = frozenset(
    {
        "node_modules", "vendor", "third_party", "third-party", "bower_components",
        "fixtures", "__fixtures__", "testdata", "test-fixtures", ".venv", "venv",
        "site-packages", "dist", "build", "target", ".next", "__pycache__",
    }
)  # fmt: skip

#: Upper bound on CI configuration files read per rule.
MAX_CI_FILES = 60

GITHUB_ACTIONS = "GitHub Actions"

_CI_PROVIDERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (GITHUB_ACTIONS, (".github/workflows/*.yml", ".github/workflows/*.yaml")),
    ("GitLab CI", (".gitlab-ci.yml", ".gitlab-ci.yaml", ".gitlab/ci/**/*.yml")),
    ("CircleCI", (".circleci/config.yml", ".circleci/config.yaml")),
    ("Jenkins", ("Jenkinsfile", "Jenkinsfile.*")),
    (
        "Azure Pipelines",
        ("azure-pipelines.yml", "azure-pipelines.yaml", ".azure-pipelines/**/*.yml"),
    ),
    ("Bitbucket Pipelines", ("bitbucket-pipelines.yml",)),
    ("Travis CI", (".travis.yml",)),
    ("Drone", (".drone.yml", ".drone.yaml")),
    (
        "Woodpecker",
        (".woodpecker.yml", ".woodpecker.yaml", ".woodpecker/*.yml", ".woodpecker/*.yaml"),
    ),
    ("Buildkite", (".buildkite/*.yml", ".buildkite/*.yaml")),
)


def is_vendored(path: str) -> bool:
    """True when any directory component marks the file as vendored/generated/fixture."""
    return any(part.lower() in VENDORED_DIRS for part in PurePosixPath(path).parts[:-1])


def load_yaml(text: str | None) -> Any:
    """``yaml.safe_load`` that returns ``None`` for unreadable or malformed input."""
    if text is None:
        return None
    try:
        return yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError):
        return None


@dataclass(frozen=True)
class CiFiles:
    """CI configuration files found in a repo, grouped by provider (sorted, capped)."""

    by_provider: tuple[tuple[str, tuple[str, ...]], ...]
    truncated: bool

    @property
    def providers(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.by_provider)

    @property
    def files(self) -> tuple[str, ...]:
        return tuple(f for _, files in self.by_provider for f in files)

    @property
    def workflows(self) -> tuple[str, ...]:
        """GitHub Actions workflow files only."""
        return tuple(f for name, files in self.by_provider if name == GITHUB_ACTIONS for f in files)

    @property
    def cap_note(self) -> str:
        return f" (only the first {MAX_CI_FILES} CI files were read)" if self.truncated else ""


def ci_files(repo: RepoSnapshot) -> CiFiles:
    """Locate CI configuration for every supported provider."""
    found: list[tuple[str, tuple[str, ...]]] = []
    budget = MAX_CI_FILES
    truncated = False
    for name, globs in _CI_PROVIDERS:
        matches = repo.glob(*globs)
        if not matches:
            continue
        if len(matches) > budget:
            truncated = True
            matches = matches[:budget]
        budget -= len(matches)
        if matches:
            found.append((name, tuple(matches)))
    return CiFiles(tuple(found), truncated)


def code_lines(repo: RepoSnapshot, path: str) -> list[tuple[int, str]]:
    """``(line_no, text)`` for every line that is not blank or a ``#`` / ``//`` comment."""
    out: list[tuple[int, str]] = []
    for no, line in enumerate(repo.read_lines(path), start=1):
        stripped = line.strip()
        if stripped and not stripped.startswith(("#", "//")):
            out.append((no, line))
    return out
