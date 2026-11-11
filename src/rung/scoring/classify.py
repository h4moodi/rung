"""Scores, the stage ladder and stage-aware severity.

All functions are pure and work on :class:`RuleResult` only, so the model can be tested
(and explained in the thesis) without running a single rule.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from rung.models import (
    DIMENSION_ORDER,
    STAGE_ORDER,
    Classification,
    DimensionScore,
    Outcome,
    Priority,
    RuleResult,
    Severity,
    Stage,
    StageProgress,
)

#: Absorbs float noise when weights such as 0.7 + 0.1 + 0.2 are summed, so that a stage
#: sitting exactly on the threshold counts as met.
_EPSILON = 1e-9


def _ratio(results: Iterable[RuleResult]) -> float | None:
    """Weighted share of applicable rules that passed; ``None`` if none are applicable."""
    passed = total = 0.0
    for result in results:
        if result.outcome is Outcome.not_applicable:
            continue
        total += result.weight
        if result.outcome is Outcome.passed:
            passed += result.weight
    return passed / total if total > 0 else None


def _count(results: Sequence[RuleResult], outcome: Outcome) -> int:
    return sum(1 for r in results if r.outcome is outcome)


def overall_score(results: Sequence[RuleResult]) -> float:
    """0-100: weighted percentage of applicable rules passed (100 if none apply)."""
    ratio = _ratio(results)
    return 100.0 if ratio is None else round(100.0 * ratio, 1)


def score_dimensions(results: Sequence[RuleResult]) -> list[DimensionScore]:
    """One score per dimension, always all six, in ``DIMENSION_ORDER``."""
    scores = []
    for dimension in DIMENSION_ORDER:
        own = [r for r in results if r.dimension is dimension]
        scores.append(
            DimensionScore(
                dimension=dimension,
                score=overall_score(own),
                passed=_count(own, Outcome.passed),
                failed=_count(own, Outcome.failed),
                not_applicable=_count(own, Outcome.not_applicable),
            )
        )
    return scores


def _percent(value: float) -> str:
    return f"{value * 100:.0f}%"


def _rationale(stage: Stage, progress: Sequence[StageProgress], threshold: float) -> str:
    by_stage = {p.stage: p for p in progress}
    bar = _percent(threshold)
    if not by_stage[Stage.inception].met:
        return (
            f"Classified as inception, the floor of the ladder: inception fulfillment is "
            f"{_percent(by_stage[Stage.inception].fulfillment)}, below the {bar} threshold."
        )
    met = ", ".join(
        f"{s.value} {_percent(by_stage[s].fulfillment)}" for s in STAGE_ORDER[: stage.order + 1]
    )
    text = f"Classified as {stage.value}: every stage up to it meets the {bar} threshold ({met})."
    if stage.next is None:
        return text
    blocker = by_stage[stage.next]
    return f"{text} {stage.next.value} is at {_percent(blocker.fulfillment)} and is not met yet."


def classify(results: Sequence[RuleResult], threshold: float) -> Classification:
    """Place the repository on the ladder.

    A stage is met when its fulfillment reaches ``threshold``; the classified stage is the
    highest one whose every predecessor is met too, with inception as the floor.
    """
    progress = []
    for stage in STAGE_ORDER:
        own = [r for r in results if r.stage is stage]
        ratio = _ratio(own)
        fulfillment = 1.0 if ratio is None else ratio
        progress.append(
            StageProgress(
                stage=stage,
                fulfillment=round(fulfillment, 4),
                passed=_count(own, Outcome.passed),
                total=sum(1 for r in own if r.outcome is not Outcome.not_applicable),
                met=fulfillment >= threshold - _EPSILON,
            )
        )
    classified = Stage.inception
    for item in progress:
        if not item.met:
            break
        classified = item.stage
    return Classification(
        stage=classified,
        next_stage=classified.next,
        threshold=threshold,
        progress=progress,
        rationale=_rationale(classified, progress, threshold),
    )


def priority_for(rule_stage: Stage, classified: Stage) -> Priority:
    """``overdue`` at or below the classified stage, ``next`` one rung up, else ``later``."""
    distance = rule_stage.order - classified.order
    if distance <= 0:
        return "overdue"
    return "next" if distance == 1 else "later"


def effective_severity(base: Severity, rule_stage: Stage, classified: Stage) -> Severity:
    """Stage-aware severity: gaps beyond the next rung are reported as ``info``."""
    return Severity.info if priority_for(rule_stage, classified) == "later" else base
