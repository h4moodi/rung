"""The audit engine: collect -> analyze -> score.

``run_audit`` is the single entry point shared by the CLI and the API. It never writes to
the audited directory, never aborts because one rule crashed, and produces the same
report for the same repository state and configuration (``summary.duration_ms`` aside).
"""

from __future__ import annotations

import os
import time
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from rung import __version__
from rung.collect import RepoSnapshot
from rung.config import Config, ConfigError, load_config
from rung.models import (
    AuditReport,
    Check,
    Confidence,
    Finding,
    Hit,
    Location,
    Outcome,
    RepoInfo,
    Rule,
    RuleResult,
    Severity,
    Summary,
    Suppression,
    ToolInfo,
    fingerprint,
)
from rung.registry import Registry, load_builtin_rules
from rung.scoring import (
    build_checklist,
    classify,
    effective_severity,
    overall_score,
    score_dimensions,
)

_MAX_ERROR_CHARS = 200


class _RuleContractError(Exception):
    """A rule returned something that is not valid, evidence-based output."""


def _describe_error(exc: BaseException) -> str:
    """``"<ExcType>: <message>"`` on one line, truncated. Never a traceback."""
    name = "RuleContractError" if isinstance(exc, _RuleContractError) else type(exc).__name__
    message = " ".join(str(exc).split())
    if len(message) > _MAX_ERROR_CHARS:
        message = message[: _MAX_ERROR_CHARS - 3] + "..."
    return f"{name}: {message}" if message else name


def _validate_rule_ids(config: Config, registry: Registry) -> None:
    sources: tuple[tuple[str, Iterable[str]], ...] = (
        ("rules.disable", config.disable),
        ("rules.severity", config.severity_overrides),
        ("baseline", (entry.rule_id for entry in config.baseline)),
    )
    for where, ids in sources:
        unknown = sorted(rule_id for rule_id in set(ids) if rule_id not in registry)
        if unknown:
            raise ConfigError(f"unknown rule id {unknown[0]!r} in {where}")


def _hit_severity(hit: Hit, rule: Rule, override: Severity | None) -> Severity:
    """Per-hit severity before stage adjustment.

    Without a config override the hit's own severity (or the rule default) is used. With
    one, the override replaces the rule default and also caps hit-level severities: a hit
    the rule marked lower stays lower, a hit it marked higher is brought down to what the
    user configured.
    """
    if override is None:
        return hit.severity or rule.severity
    if hit.severity is not None and hit.severity.rank < override.rank:
        return hit.severity
    return override


def _line_span(hit: Hit) -> tuple[int | None, int | None]:
    """A usable (start, end) pair: 1-based, end only alongside a start and not before it."""
    if hit.line is None or hit.line < 1:
        return None, None
    if hit.end_line is None or hit.end_line < hit.line:
        return hit.line, None
    return hit.line, hit.end_line


class _Fingerprinter:
    """Content-anchored fingerprints, with a deterministic tie-break for duplicates."""

    def __init__(self, repo: RepoSnapshot) -> None:
        self._repo = repo
        self._lines: dict[str, list[str]] = {}
        self._seen: Counter[str] = Counter()

    def _anchor(self, hit: Hit, line: int | None) -> str:
        if line is not None:
            if hit.path not in self._lines:
                self._lines[hit.path] = self._repo.read_lines(hit.path)
            lines = self._lines[hit.path]
            if line <= len(lines) and lines[line - 1].strip():
                return lines[line - 1].strip()
        return hit.message

    def make(self, rule_id: str, hit: Hit, line: int | None) -> str:
        anchor = self._anchor(hit, line)
        base = fingerprint(rule_id, hit.path, anchor)
        occurrence = self._seen[base]
        self._seen[base] += 1
        if occurrence == 0:
            return base
        return fingerprint(rule_id, hit.path, f"{anchor}\x00{occurrence}")


def _run_rule(rule: Rule, repo: RepoSnapshot) -> Check:
    check = rule.run(repo)
    if not isinstance(check, Check):
        raise _RuleContractError(f"returned {type(check).__name__}, expected Check")
    if check.outcome is Outcome.failed and not check.hits:
        raise _RuleContractError("failed without any hit; a finding needs a location")
    if any(not isinstance(hit.path, str) or not hit.path.strip() for hit in check.hits):
        raise _RuleContractError("produced a hit with an empty path")
    return check


def _analyze(
    repo: RepoSnapshot, config: Config, registry: Registry
) -> tuple[list[RuleResult], list[Finding]]:
    """Run every enabled rule in id order. Findings carry their pre-adjustment severity."""
    results: list[RuleResult] = []
    findings: list[Finding] = []
    fingerprints = _Fingerprinter(repo)
    for rule in registry:
        if rule.id in config.disable:
            continue
        override = config.severity_overrides.get(rule.id)
        result = RuleResult(
            rule_id=rule.id,
            title=rule.title,
            dimension=rule.dimension,
            stage=rule.stage,
            weight=rule.weight,
            severity=override or rule.severity,
            confidence=rule.confidence,
            outcome=Outcome.not_applicable,
            summary="",
        )
        try:
            check = _run_rule(rule, repo)
        except Exception as exc:  # one broken rule must not end the audit
            error = _describe_error(exc)
            results.append(
                result.model_copy(update={"summary": "Rule crashed; skipped", "error": error})
            )
            continue
        results.append(
            result.model_copy(
                update={
                    "outcome": check.outcome,
                    "summary": check.summary,
                    "evidence": list(check.evidence),
                }
            )
        )
        if check.outcome is not Outcome.failed:
            continue
        # Sorted, so the occurrence index of duplicate anchors does not depend on the
        # order in which the rule happened to emit its hits.
        ordered = sorted(
            check.hits, key=lambda h: (h.path, h.line or 0, h.end_line or 0, h.message)
        )
        for hit in ordered:
            line, end_line = _line_span(hit)
            severity = _hit_severity(hit, rule, override)
            confidence: Confidence = hit.confidence or rule.confidence
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    dimension=rule.dimension,
                    stage=rule.stage,
                    severity=severity,
                    base_severity=severity,
                    confidence=confidence,
                    message=hit.message,
                    remediation=rule.remediation,
                    location=Location(path=hit.path, start_line=line, end_line=end_line),
                    fingerprint=fingerprints.make(rule.id, hit, line),
                )
            )
    return results, findings


def _repo_name(root: Path, source: str | None) -> str:
    if source:
        tail = source.rstrip("/").replace("\\", "/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
        tail = tail.removesuffix(".git")
        if tail and tail not in {".", ".."}:
            return tail
    return root.name or str(root)


def _finding_order(finding: Finding) -> tuple[int, str, str, int, str]:
    return (
        -finding.severity.rank,
        finding.rule_id,
        finding.location.path,
        finding.location.start_line or 0,
        finding.fingerprint,
    )


def run_audit(
    path: str | os.PathLike[str],
    *,
    config: Config | None = None,
    registry: Registry | None = None,
    source: str | None = None,
) -> AuditReport:
    """Audit the repository at ``path`` and return the complete report.

    Raises ``NotADirectoryError`` for a bad path and :class:`ConfigError` for an invalid
    configuration, including rule ids the registry does not know.
    """
    started = time.perf_counter()
    if config is None:
        config = load_config(Path(path))
    if registry is None:
        registry = load_builtin_rules()
    _validate_rule_ids(config, registry)

    repo = RepoSnapshot(Path(path), ignore=config.ignore_paths, max_commits=config.max_commits)
    results, raw_findings = _analyze(repo, config, registry)
    classification = classify(results, config.stage_threshold)

    baseline = {(entry.rule_id, entry.fingerprint): entry for entry in config.baseline}
    findings: list[Finding] = []
    suppressed: list[Suppression] = []
    for raw in raw_findings:
        entry = baseline.get((raw.rule_id, raw.fingerprint))
        if entry is not None:
            suppressed.append(
                Suppression(
                    fingerprint=raw.fingerprint,
                    rule_id=raw.rule_id,
                    path=raw.location.path,
                    justification=entry.justification,
                )
            )
            continue
        adjusted = effective_severity(raw.base_severity, raw.stage, classification.stage)
        findings.append(raw.model_copy(update={"severity": adjusted}))
    findings.sort(key=_finding_order)
    suppressed.sort(key=lambda s: (s.rule_id, s.path, s.fingerprint))

    # finding_count is the number of *reported* findings, so the per-rule counts always
    # add up to len(report.findings).
    reported = Counter(finding.rule_id for finding in findings)
    results = [r.model_copy(update={"finding_count": reported[r.rule_id]}) for r in results]

    counts = Counter(finding.severity for finding in findings)
    outcomes = Counter(result.outcome for result in results)
    return AuditReport(
        tool=ToolInfo(version=__version__),
        repo=RepoInfo(
            name=_repo_name(repo.root, source),
            source=source if source is not None else os.fspath(path),
            is_git=repo.is_git,
            head_commit=repo.head,
            head_date=repo.head_date.isoformat() if repo.head_date else None,
            branch=repo.branch,
            shallow=repo.is_shallow,
        ),
        classification=classification,
        overall_score=overall_score(results),
        dimensions=score_dimensions(results),
        rules=results,
        findings=findings,
        checklist=build_checklist(
            results,
            findings,
            classification.stage,
            remediations={rule.id: rule.remediation for rule in registry},
        ),
        suppressed=suppressed,
        summary=Summary(
            counts_by_severity={severity: counts[severity] for severity in Severity},
            rules_run=len(results),
            rules_passed=outcomes[Outcome.passed],
            rules_failed=outcomes[Outcome.failed],
            rules_not_applicable=outcomes[Outcome.not_applicable],
            files_scanned=len(repo.files),
            commits_analyzed=len(repo.commits),
            suppressed=len(suppressed),
            duration_ms=int((time.perf_counter() - started) * 1000),
        ),
    )


def has_blocking_findings(report: AuditReport, fail_on: Severity) -> bool:
    """True when a reported finding is at or above ``fail_on`` (CLI exit code 1)."""
    return any(finding.severity.rank >= fail_on.rank for finding in report.findings)
