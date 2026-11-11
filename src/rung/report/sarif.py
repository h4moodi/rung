"""SARIF 2.1.0 rendering, shaped for GitHub code scanning."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from rung.models import AuditReport, Confidence, Dimension, RuleResult, Severity
from rung.registry import Registry
from rung.scoring import priority_for

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/h4moodi/rung"
FINGERPRINT_KEY = "rungFingerprint/v1"

_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "note",
}
#: GitHub buckets: >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
_SECURITY_SEVERITY = {
    Severity.critical: "9.5",
    Severity.high: "8.0",
    Severity.medium: "5.5",
    Severity.low: "3.0",
    Severity.info: "1.0",
}
_PRECISION = {Confidence.high: "high", Confidence.medium: "medium", Confidence.low: "low"}


def _pascal(title: str) -> str:
    return "".join(word[:1].upper() + word[1:] for word in re.findall(r"[A-Za-z0-9]+", title))


def _location(path: str, start: int | None = None, end: int | None = None) -> dict[str, Any]:
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": quote(path, safe="/"), "uriBaseId": "%SRCROOT%"}
    }
    if start is not None:
        region = {"startLine": start}
        if end is not None:
            region["endLine"] = end
        physical["region"] = region
    return {"physicalLocation": physical}


def _descriptor(
    result: RuleResult, remediation: str | None, registry: Registry | None
) -> dict[str, Any]:
    known = registry.get(result.rule_id) if registry and result.rule_id in registry else None
    tags = [result.dimension.value, f"stage:{result.stage.value}"]
    if result.dimension is Dimension.security:
        tags.append("security")
    tags += sorted(t for t in (known.tags if known else ()) if t not in tags)
    properties: dict[str, Any] = {
        "dimension": result.dimension.value,
        "stage": result.stage.value,
        "tags": tags,
        "precision": _PRECISION[result.confidence],
    }
    if result.dimension is Dimension.security:
        properties["security-severity"] = _SECURITY_SEVERITY[result.severity]
    descriptor: dict[str, Any] = {
        "id": result.rule_id,
        "name": _pascal(result.title) or result.rule_id,
        "shortDescription": {"text": result.title},
        "fullDescription": {"text": known.description if known else result.title},
        "defaultConfiguration": {"level": _LEVEL[result.severity]},
        "properties": properties,
    }
    help_text = known.remediation if known else remediation
    if help_text:
        descriptor["help"] = {"text": help_text}
    return descriptor


def to_sarif(report: AuditReport, *, registry: Registry | None = None) -> dict[str, Any]:
    """Render ``report`` as a SARIF 2.1.0 log (a JSON-serialisable dict).

    The result depends on the report alone. Passing ``registry`` only enriches the rule
    descriptors with each rule's long description, remediation and tags.
    """
    remediation = {item.rule_id: item.remediation for item in report.checklist}
    index = {result.rule_id: i for i, result in enumerate(report.rules)}
    by_id = {result.rule_id: result for result in report.rules}
    classified = report.classification.stage

    results: list[dict[str, Any]] = []
    for finding in report.findings:
        properties = {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "stage": finding.stage.value,
            "priority": priority_for(finding.stage, classified),
        }
        if finding.dimension is Dimension.security:
            properties["security-severity"] = _SECURITY_SEVERITY[finding.severity]
        loc = finding.location
        entry: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _LEVEL[finding.severity],
            "message": {"text": finding.message},
            "locations": [_location(loc.path, loc.start_line, loc.end_line)],
            "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
            "suppressions": [],
            "properties": properties,
        }
        if finding.rule_id in index:
            entry["ruleIndex"] = index[finding.rule_id]
        results.append(entry)
    for supp in report.suppressed:
        rule = by_id.get(supp.rule_id)
        entry = {
            "ruleId": supp.rule_id,
            "level": _LEVEL[rule.severity] if rule else "note",
            "message": {"text": f"{rule.title if rule else supp.rule_id} (accepted in baseline)"},
            "locations": [_location(supp.path)],
            "partialFingerprints": {FINGERPRINT_KEY: supp.fingerprint},
            "suppressions": [{"kind": "external", "justification": supp.justification}],
        }
        if rule:
            entry["ruleIndex"] = index[supp.rule_id]
        results.append(entry)

    run = {
        "tool": {
            "driver": {
                "name": report.tool.name,
                "version": report.tool.version,
                "informationUri": INFORMATION_URI,
                "rules": [
                    _descriptor(r, remediation.get(r.rule_id), registry) for r in report.rules
                ],
            }
        },
        "results": results,
        "columnKind": "utf16CodeUnits",
        "properties": {
            "classification": report.classification.model_dump(mode="json"),
            "overallScore": report.overall_score,
            "repository": report.repo.name,
            "headCommit": report.repo.head_commit,
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
