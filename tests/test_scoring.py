from __future__ import annotations

import pytest

from rung.models import (
    DIMENSION_ORDER,
    STAGE_ORDER,
    Confidence,
    Dimension,
    Finding,
    Location,
    Outcome,
    RuleResult,
    Severity,
    Stage,
)
from rung.scoring import (
    STAGE_INFO,
    build_checklist,
    classify,
    effective_severity,
    overall_score,
    priority_for,
    score_dimensions,
)

P, F, NA = Outcome.passed, Outcome.failed, Outcome.not_applicable


def rr(
    rule_id: str,
    stage: Stage,
    outcome: Outcome,
    *,
    weight: float = 1.0,
    dimension: Dimension = Dimension.docs,
    severity: Severity = Severity.medium,
) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        title=f"Title of {rule_id}",
        dimension=dimension,
        stage=stage,
        weight=weight,
        severity=severity,
        confidence=Confidence.high,
        outcome=outcome,
        summary="s",
    )


def stage_block(stage: Stage, passed: int, failed: int, prefix: str) -> list[RuleResult]:
    outcomes = [P] * passed + [F] * failed
    return [rr(f"{prefix}{i:03d}", stage, o) for i, o in enumerate(outcomes, start=1)]


def finding(result: RuleResult, severity: Severity, base: Severity | None = None) -> Finding:
    return Finding(
        rule_id=result.rule_id,
        title=result.title,
        dimension=result.dimension,
        stage=result.stage,
        severity=severity,
        base_severity=base or severity,
        confidence=Confidence.high,
        message="m",
        remediation=f"Fix {result.rule_id}",
        location=Location(path="a.txt"),
        fingerprint=f"fp-{result.rule_id}",
    )


# ------------------------------------------------------------------- classification


def test_all_stages_met_is_maturity_with_no_next_stage():
    results = [rr(f"AAA00{i}", s, P) for i, s in enumerate(STAGE_ORDER)]
    c = classify(results, 0.7)
    assert c.stage is Stage.maturity and c.next_stage is None
    assert [p.stage for p in c.progress] == list(STAGE_ORDER)
    assert all(p.met and p.fulfillment == 1.0 for p in c.progress)
    assert "maturity" in c.rationale


def test_ladder_gating_later_stage_met_but_earlier_not():
    results = (
        stage_block(Stage.inception, 3, 0, "INC")
        + stage_block(Stage.stabilization, 1, 3, "STA")
        + stage_block(Stage.growth, 4, 0, "GRO")
        + stage_block(Stage.maturity, 4, 0, "MAT")
    )
    c = classify(results, 0.7)
    assert c.stage is Stage.inception and c.next_stage is Stage.stabilization
    met = {p.stage: p.met for p in c.progress}
    assert met == {
        Stage.inception: True,
        Stage.stabilization: False,
        Stage.growth: True,
        Stage.maturity: True,
    }
    assert "stabilization is at 25%" in c.rationale


def test_inception_is_the_floor_even_when_not_met():
    results = stage_block(Stage.inception, 1, 3, "INC") + stage_block(Stage.growth, 2, 0, "GRO")
    c = classify(results, 0.7)
    assert c.stage is Stage.inception and c.next_stage is Stage.stabilization
    assert c.progress[0].met is False and c.progress[0].fulfillment == 0.25
    assert "floor" in c.rationale


def test_threshold_boundary_exactly_seventy_percent_is_met():
    at = classify(stage_block(Stage.inception, 7, 3, "INC"), 0.70)
    assert at.progress[0].fulfillment == 0.7 and at.progress[0].met
    below = classify(stage_block(Stage.inception, 69, 31, "INC"), 0.70)
    assert below.progress[0].fulfillment == 0.69 and not below.progress[0].met


def test_threshold_boundary_survives_float_noise_in_weights():
    # 1.05 of 1.5 is exactly 70%, but the float arithmetic lands a hair below it.
    assert (0.35 + 0.7) / (0.35 + 0.7 + 0.05 + 0.4) < 0.7
    results = [
        rr("INC001", Stage.inception, P, weight=0.35),
        rr("INC002", Stage.inception, P, weight=0.7),
        rr("INC003", Stage.inception, F, weight=0.05),
        rr("INC004", Stage.inception, F, weight=0.4),
    ]
    assert classify(results, 0.7).progress[0].met


def test_not_applicable_rules_are_excluded():
    results = [
        rr("INC001", Stage.inception, P),
        rr("INC002", Stage.inception, NA, weight=50),
        rr("INC003", Stage.inception, NA),
    ]
    progress = classify(results, 0.7).progress[0]
    assert (progress.fulfillment, progress.passed, progress.total, progress.met) == (
        1.0,
        1,
        1,
        True,
    )
    assert overall_score(results) == 100.0


def test_empty_stage_counts_as_met():
    results = stage_block(Stage.inception, 1, 0, "INC") + [rr("STA001", Stage.stabilization, NA)]
    c = classify(results, 0.7)
    assert c.stage is Stage.maturity
    assert [(p.fulfillment, p.total, p.met) for p in c.progress[1:]] == [(1.0, 0, True)] * 3
    assert classify([], 0.7).stage is Stage.maturity


def test_weights_drive_fulfillment():
    heavy_pass = [
        rr("INC001", Stage.inception, P, weight=3),
        rr("INC002", Stage.inception, F, weight=1),
    ]
    heavy_fail = [
        rr("INC001", Stage.inception, F, weight=3),
        rr("INC002", Stage.inception, P, weight=1),
    ]
    assert classify(heavy_pass, 0.7).progress[0].fulfillment == 0.75
    assert classify(heavy_pass, 0.7).progress[0].met
    assert classify(heavy_fail, 0.7).progress[0].fulfillment == 0.25
    assert overall_score(heavy_pass) == 75.0 and overall_score(heavy_fail) == 25.0


def test_threshold_is_configurable_and_recorded():
    results = stage_block(Stage.inception, 1, 1, "INC")
    assert classify(results, 0.5).progress[0].met
    assert not classify(results, 0.51).progress[0].met
    assert classify(results, 0.5).threshold == 0.5


# ------------------------------------------------------- stage-aware severity/priority


@pytest.mark.parametrize(
    ("rule_stage", "classified", "priority"),
    [
        (Stage.inception, Stage.inception, "overdue"),
        (Stage.inception, Stage.maturity, "overdue"),
        (Stage.stabilization, Stage.growth, "overdue"),
        (Stage.stabilization, Stage.inception, "next"),
        (Stage.maturity, Stage.growth, "next"),
        (Stage.growth, Stage.inception, "later"),
        (Stage.maturity, Stage.inception, "later"),
        (Stage.maturity, Stage.stabilization, "later"),
    ],
)
def test_priority_and_effective_severity(rule_stage, classified, priority):
    assert priority_for(rule_stage, classified) == priority
    expected = Severity.info if priority == "later" else Severity.high
    assert effective_severity(Severity.high, rule_stage, classified) is expected


def test_inception_rules_are_never_down_ranked():
    for classified in STAGE_ORDER:
        assert (
            effective_severity(Severity.critical, Stage.inception, classified) is Severity.critical
        )


# --------------------------------------------------------------------- dimension scores


def test_dimension_scores_cover_all_six_in_order():
    results = [
        rr("DOC001", Stage.inception, P, dimension=Dimension.docs, weight=3),
        rr("DOC002", Stage.growth, F, dimension=Dimension.docs, weight=1),
        rr("DOC003", Stage.growth, NA, dimension=Dimension.docs),
        rr("SEC001", Stage.inception, F, dimension=Dimension.security),
        rr("TST001", Stage.stabilization, NA, dimension=Dimension.tests),
    ]
    scores = score_dimensions(results)
    assert [s.dimension for s in scores] == list(DIMENSION_ORDER) and len(scores) == 6
    by = {s.dimension: s for s in scores}
    docs = by[Dimension.docs]
    assert (docs.score, docs.passed, docs.failed, docs.not_applicable) == (75.0, 1, 1, 1)
    assert by[Dimension.security].score == 0.0
    assert by[Dimension.tests].score == 100.0 and by[Dimension.tests].not_applicable == 1
    assert by[Dimension.cicd].score == 100.0 and by[Dimension.cicd].passed == 0
    assert overall_score(results) == 60.0


# ---------------------------------------------------------------------------- checklist


def test_checklist_orders_by_priority_then_severity_then_weight_then_id():
    results = [
        rr("MAT001", Stage.maturity, F, severity=Severity.critical),
        rr("GRO001", Stage.growth, F, severity=Severity.high),
        rr("STA003", Stage.stabilization, F, severity=Severity.medium, weight=1),
        rr("STA002", Stage.stabilization, F, severity=Severity.medium, weight=2),
        rr("STA001", Stage.stabilization, F, severity=Severity.medium, weight=1),
        rr("INC002", Stage.inception, F, severity=Severity.low),
        rr("INC001", Stage.inception, F, severity=Severity.high),
        rr("INC003", Stage.inception, P),
        rr("INC004", Stage.inception, NA),
    ]
    classified = Stage.stabilization
    findings = [
        finding(r, effective_severity(r.severity, r.stage, classified), r.severity)
        for r in results
        if r.outcome is F
    ]
    items = build_checklist(results, findings, classified)
    assert [i.rule_id for i in items] == [
        "INC001", "STA002", "STA001", "STA003", "INC002", "GRO001", "MAT001",
    ]  # fmt: skip
    assert [i.rank for i in items] == list(range(1, 8))
    assert [i.priority for i in items] == ["overdue"] * 5 + ["next", "later"]
    last = items[-1]
    assert last.severity is Severity.info and last.remediation == "Fix MAT001"
    assert all(i.finding_count == 1 for i in items)


def test_checklist_uses_worst_finding_severity_and_counts_findings():
    result = rr("STA001", Stage.stabilization, F, severity=Severity.low)
    other = rr("STA002", Stage.stabilization, F, severity=Severity.medium)
    findings = [finding(result, Severity.low), finding(result, Severity.critical)]
    items = build_checklist(
        [other, result], findings + [finding(other, Severity.medium)], Stage.growth
    )
    assert [i.rule_id for i in items] == ["STA001", "STA002"]
    assert items[0].severity is Severity.critical and items[0].finding_count == 2


def test_checklist_keeps_fully_suppressed_rules():
    result = rr("GRO001", Stage.growth, F, severity=Severity.high)
    items = build_checklist([result], [], Stage.inception, remediations={"GRO001": "Do the thing"})
    assert len(items) == 1
    item = items[0]
    assert (item.finding_count, item.severity, item.priority) == (0, Severity.info, "later")
    assert item.remediation == "Do the thing"
    assert build_checklist([result], [], Stage.inception)[0].remediation == ""


# ------------------------------------------------------------------------------- stages


def test_stage_info_covers_the_ladder_in_order():
    assert tuple(info.stage for info in STAGE_INFO) == STAGE_ORDER
    assert all(info.title and info.summary and info.expectations for info in STAGE_INFO)
