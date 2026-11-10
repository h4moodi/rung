"""Core data contracts for rung.

Everything that crosses a module boundary (rule -> engine -> report -> API -> dashboard)
is defined here. The JSON form of :class:`AuditReport` is the public output schema;
changing a field here is a breaking change and must bump ``SCHEMA_VERSION``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # pragma: no cover
    from rung.collect import RepoSnapshot

SCHEMA_VERSION = "1.0"


# --------------------------------------------------------------------------- enums


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        """Higher is worse. ``info`` = 0, ``critical`` = 4."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


class Confidence(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"


class Stage(StrEnum):
    """Start-up life-cycle stages from Klotins et al. (2021), in ladder order."""

    inception = "inception"
    stabilization = "stabilization"
    growth = "growth"
    maturity = "maturity"

    @property
    def order(self) -> int:
        return STAGE_ORDER.index(self)

    @property
    def next(self) -> Stage | None:
        i = self.order + 1
        return STAGE_ORDER[i] if i < len(STAGE_ORDER) else None


STAGE_ORDER: tuple[Stage, ...] = (
    Stage.inception,
    Stage.stabilization,
    Stage.growth,
    Stage.maturity,
)


class Dimension(StrEnum):
    """The six audited artifacts from the project proposal. One probe module each."""

    commits = "commit_history"
    containers = "containerization"
    tests = "testing"
    cicd = "ci_cd"
    docs = "documentation"
    security = "security"


DIMENSION_ORDER: tuple[Dimension, ...] = tuple(Dimension)


class Outcome(StrEnum):
    passed = "passed"
    failed = "failed"
    not_applicable = "not_applicable"


# ------------------------------------------------------------- rule-author surface


class Location(BaseModel):
    """Where in the audited repo something was observed. Paths are repo-relative POSIX."""

    model_config = ConfigDict(frozen=True)

    path: str
    start_line: int | None = None
    end_line: int | None = None


@dataclass(frozen=True)
class Hit:
    """One piece of failing evidence produced by a rule.

    ``path`` is required: for a *missing* artifact use the path where it is expected
    (e.g. ``"README.md"``, ``".github/workflows"``) and leave ``line`` as ``None``.
    ``message`` must never contain a secret value: redact with :func:`rung.redact.redact`.
    ``severity`` / ``confidence`` override the rule defaults for this hit only.
    """

    path: str
    message: str
    line: int | None = None
    end_line: int | None = None
    severity: Severity | None = None
    confidence: Confidence | None = None


@dataclass(frozen=True)
class Check:
    """What a rule's ``run`` function returns. Build it with ``ok`` / ``fail`` / ``na``."""

    outcome: Outcome
    summary: str
    hits: tuple[Hit, ...] = ()
    evidence: tuple[Location, ...] = ()

    @classmethod
    def ok(cls, summary: str, evidence: Sequence[Location | str] = ()) -> Check:
        """The practice is in place. ``evidence`` points at the files that prove it."""
        return cls(Outcome.passed, summary, evidence=_locations(evidence))

    @classmethod
    def fail(
        cls,
        summary: str,
        hits: Sequence[Hit] = (),
        *,
        at: str | None = None,
        line: int | None = None,
    ) -> Check:
        """The practice is missing or violated.

        Either pass explicit ``hits`` or use the ``at=`` shorthand for a single hit whose
        message is ``summary``. One of the two is required: a failure with no location is
        not evidence-based.
        """
        if not hits:
            if at is None:
                raise ValueError("Check.fail needs hits=[...] or at='<path>'")
            hits = (Hit(path=at, message=summary, line=line),)
        return cls(Outcome.failed, summary, hits=tuple(hits))

    @classmethod
    def na(cls, summary: str) -> Check:
        """The rule does not apply (e.g. Dockerfile rules on a repo with no Dockerfile).

        Not-applicable rules are excluded from scoring entirely.
        """
        return cls(Outcome.not_applicable, summary)


def _locations(items: Sequence[Location | str]) -> tuple[Location, ...]:
    return tuple(Location(path=i) if isinstance(i, str) else i for i in items)


@dataclass(frozen=True)
class Rule:
    """A single, independent check. Register with :func:`rung.registry.rule`.

    ``stage`` is the life-cycle stage at which the practice becomes *expected*. It drives
    both classification (a stage is reached when enough of its rules pass) and stage-aware
    severity (a missing maturity practice in an inception-stage repo is reported as info).
    ``weight`` is the rule's relative importance inside its stage and dimension.
    """

    id: str
    title: str
    dimension: Dimension
    stage: Stage
    severity: Severity
    confidence: Confidence
    description: str
    remediation: str
    run: Callable[[RepoSnapshot], Check]
    weight: float = 1.0
    tags: tuple[str, ...] = field(default=())


# ------------------------------------------------------------------ report schema


class Finding(BaseModel):
    """A reported problem with full evidence. Never contains a secret value."""

    rule_id: str
    title: str
    dimension: Dimension
    stage: Stage
    severity: Severity
    base_severity: Severity
    confidence: Confidence
    message: str
    remediation: str
    location: Location
    fingerprint: str


class RuleResult(BaseModel):
    """The outcome of one rule, pass or fail, with its supporting evidence."""

    rule_id: str
    title: str
    dimension: Dimension
    stage: Stage
    weight: float
    severity: Severity
    confidence: Confidence
    outcome: Outcome
    summary: str
    evidence: list[Location] = Field(default_factory=list)
    finding_count: int = 0
    error: str | None = None


class DimensionScore(BaseModel):
    dimension: Dimension
    score: float = Field(ge=0, le=100, description="Weighted % of applicable rules passed")
    passed: int
    failed: int
    not_applicable: int


class StageProgress(BaseModel):
    stage: Stage
    fulfillment: float = Field(
        ge=0, le=1, description="Weighted share of this stage's rules passed"
    )
    passed: int
    total: int
    met: bool


class Classification(BaseModel):
    stage: Stage
    next_stage: Stage | None
    threshold: float
    progress: list[StageProgress]
    rationale: str


Priority = Literal["overdue", "next", "later"]


class ChecklistItem(BaseModel):
    """One prioritized improvement. ``overdue`` = expected at or below the current stage,
    ``next`` = needed to reach the next rung, ``later`` = beyond the next rung."""

    rank: int
    rule_id: str
    title: str
    dimension: Dimension
    stage: Stage
    priority: Priority
    severity: Severity
    remediation: str
    finding_count: int


class Suppression(BaseModel):
    fingerprint: str
    rule_id: str
    path: str
    justification: str


class RepoInfo(BaseModel):
    name: str
    source: str
    is_git: bool
    head_commit: str | None = None
    head_date: str | None = None
    branch: str | None = None
    shallow: bool = False


class ToolInfo(BaseModel):
    name: str = "rung"
    version: str
    schema_version: str = SCHEMA_VERSION


class Summary(BaseModel):
    counts_by_severity: dict[Severity, int]
    rules_run: int
    rules_passed: int
    rules_failed: int
    rules_not_applicable: int
    files_scanned: int
    commits_analyzed: int
    suppressed: int
    duration_ms: int = Field(description="Wall-clock time; the only non-deterministic field")


class AuditReport(BaseModel):
    """The complete, serializable result of one audit."""

    tool: ToolInfo
    repo: RepoInfo
    classification: Classification
    overall_score: float = Field(ge=0, le=100)
    dimensions: list[DimensionScore]
    rules: list[RuleResult]
    findings: list[Finding]
    checklist: list[ChecklistItem]
    suppressed: list[Suppression] = Field(default_factory=list)
    summary: Summary


def fingerprint(rule_id: str, path: str, anchor: str) -> str:
    """Stable identity for a finding, used by baseline/suppression files.

    ``anchor`` should be content-derived (e.g. the normalized line text or a secret's
    hash), not a line number, so findings survive unrelated edits above them.
    """
    digest = hashlib.sha256(f"{rule_id}\x00{path}\x00{anchor}".encode()).hexdigest()
    return digest[:20]
