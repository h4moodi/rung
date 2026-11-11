"""The prioritized checklist: one actionable item per failed rule."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence

from rung.models import ChecklistItem, Finding, Outcome, Priority, RuleResult, Severity, Stage
from rung.scoring.classify import effective_severity, priority_for

_PRIORITY_RANK: dict[Priority, int] = {"overdue": 0, "next": 1, "later": 2}


def build_checklist(
    results: Sequence[RuleResult],
    findings: Sequence[Finding],
    classified: Stage,
    *,
    remediations: Mapping[str, str] | None = None,
) -> list[ChecklistItem]:
    """Order failed rules by priority, base severity, weight, then rule id.

    ``findings`` are the reported (non-suppressed) findings. A failed rule whose findings
    are all suppressed still gets an item: a baseline hides noise, it does not make the
    practice present. Its severity then falls back to the rule's own, and its remediation
    comes from ``remediations`` (rule id -> text), which the engine fills from the registry.
    """
    known = remediations or {}
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_rule[finding.rule_id].append(finding)

    def worst(severities: Sequence[Severity], fallback: Severity) -> Severity:
        return max(severities, key=lambda s: s.rank, default=fallback)

    drafts: list[tuple[tuple[int, int, float, str], ChecklistItem]] = []
    for result in results:
        if result.outcome is not Outcome.failed:
            continue
        own = by_rule.get(result.rule_id, [])
        priority = priority_for(result.stage, classified)
        base = worst([f.base_severity for f in own], result.severity)
        shown = worst(
            [f.severity for f in own],
            effective_severity(result.severity, result.stage, classified),
        )
        remediation = own[0].remediation if own else known.get(result.rule_id, "")
        item = ChecklistItem(
            rank=0,
            rule_id=result.rule_id,
            title=result.title,
            dimension=result.dimension,
            stage=result.stage,
            priority=priority,
            severity=shown,
            remediation=remediation,
            finding_count=len(own),
        )
        key = (_PRIORITY_RANK[priority], -base.rank, -result.weight, result.rule_id)
        drafts.append((key, item))

    drafts.sort(key=lambda pair: pair[0])
    return [item.model_copy(update={"rank": i}) for i, (_, item) in enumerate(drafts, start=1)]
