"""JSON report: the public, versioned output schema (``AuditReport``)."""

from __future__ import annotations

import json

from rung.models import AuditReport, Severity


def to_json(report: AuditReport, *, indent: int = 2) -> str:
    """Serialise with a stable key order (model field order) and a trailing newline."""
    data = report.model_dump(mode="json")
    counts = data["summary"]["counts_by_severity"]
    data["summary"]["counts_by_severity"] = {s.value: counts.get(s.value, 0) for s in Severity}
    return json.dumps(data, indent=indent, ensure_ascii=False) + "\n"
