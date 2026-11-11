"""Human-readable terminal report (rich).

Everything that comes from the audited repository is printed as plain ``Text`` after
control characters are stripped, so repository content can neither inject rich markup nor
terminal escape sequences.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable

from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule as Divider
from rich.table import Table
from rich.text import Text

from rung.models import STAGE_ORDER, AuditReport, Dimension, Rule, Severity, Stage
from rung.scoring import STAGE_INFO

DEFAULT_LIMIT = 15

_SEVERITY_STYLE = {
    Severity.critical: "bold red",
    Severity.high: "red",
    Severity.medium: "yellow",
    Severity.low: "cyan",
    Severity.info: "dim",
}
_PRIORITY_STYLE = {"overdue": "bold red", "next": "bold yellow", "later": "dim"}
_DIMENSION_LABEL = {
    Dimension.commits: "Commit history",
    Dimension.containers: "Containerization",
    Dimension.tests: "Testing",
    Dimension.cicd: "CI/CD",
    Dimension.docs: "Documentation",
    Dimension.security: "Security",
}
_BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩")


def _clean(value: str) -> str:
    """Drop control characters and bidirectional overrides from untrusted text."""
    return "".join(
        " " if unicodedata.category(ch) == "Cc" or ch in _BIDI_CONTROLS else ch for ch in value
    )


def _bar(fraction: float, width: int, ascii_only: bool) -> Text:
    filled = max(0, min(width, round(fraction * width)))
    full, empty = ("#", "-") if ascii_only else ("█", "░")
    style = "green" if fraction >= 0.7 else "yellow" if fraction >= 0.4 else "red"
    return Text(full * filled, style=style) + Text(empty * (width - filled), style="dim")


def _grid() -> Table:
    return Table.grid(padding=(0, 2))


def _heading(console: Console, title: str) -> None:
    console.print()
    console.print(Divider(Text(title, style="bold"), align="left", style="dim"))


def _ladder(report: AuditReport, console: Console, bar_width: int, ascii_only: bool) -> None:
    _heading(console, "Progression ladder")
    classified = report.classification.stage
    met_mark, open_mark, here = ("[x]", "[ ]", "<- you are here") if ascii_only else (
        "✔", "·", "◀ you are here"
    )  # fmt: skip
    grid = _grid()
    for progress in reversed(report.classification.progress):
        current = progress.stage is classified
        grid.add_row(
            Text(met_mark if progress.met else open_mark, style="green" if progress.met else "dim"),
            Text(progress.stage.value, style="bold" if current else ""),
            _bar(progress.fulfillment, bar_width, ascii_only),
            Text(f"{progress.fulfillment * 100:3.0f}%"),
            Text(f"{progress.passed}/{progress.total}", style="dim"),
            Text(here if current else "", style="bold cyan"),
        )
    console.print(Padding(grid, (0, 0, 0, 2)))
    console.print(
        Padding(
            Text(
                f"A rung is met at {report.classification.threshold * 100:.0f}% of its "
                "applicable rules, by weight; rungs must be climbed in order.",
                style="dim",
            ),
            (0, 0, 0, 2),
        )
    )


def _dimensions(report: AuditReport, console: Console, bar_width: int, ascii_only: bool) -> None:
    _heading(console, "Dimension scores")
    grid = _grid()
    for dim in report.dimensions:
        grid.add_row(
            Text(_DIMENSION_LABEL[dim.dimension]),
            _bar(dim.score / 100, bar_width, ascii_only),
            Text(f"{dim.score:5.1f}"),
            Text(f"{dim.passed} pass, {dim.failed} fail, {dim.not_applicable} n/a", style="dim"),
        )
    console.print(Padding(grid, (0, 0, 0, 2)))


def _checklist(report: AuditReport, console: Console, limit: int | None) -> None:
    _heading(console, "Checklist: what to fix, in order")
    if not report.checklist:
        console.print(Padding(Text("Nothing to fix: every applicable rule passes."), (0, 0, 0, 2)))
        return
    shown = report.checklist if limit is None else report.checklist[:limit]
    for item in shown:
        line = Text(f"{item.rank:>3}. ")
        line.append(item.priority.upper().ljust(8), style=_PRIORITY_STYLE[item.priority])
        line.append(item.severity.value.ljust(9), style=_SEVERITY_STYLE[item.severity])
        line.append(f"{item.rule_id}  ", style="bold")
        line.append(_clean(item.title))
        line.append(f"  ({item.stage.value})", style="dim")
        console.print(line)
        if item.remediation:
            console.print(Padding(Text(_clean(item.remediation), style="dim"), (0, 0, 0, 5)))
    hidden = len(report.checklist) - len(shown)
    if hidden:
        console.print(
            Padding(Text(f"... and {hidden} more (use --all)", style="dim"), (0, 0, 0, 5))
        )


def _findings(report: AuditReport, console: Console, limit: int | None) -> None:
    _heading(console, "Findings")
    if not report.findings:
        console.print(Padding(Text("No findings."), (0, 0, 0, 2)))
        return
    for severity in Severity:
        group = [f for f in report.findings if f.severity is severity]
        if not group:
            continue
        console.print(
            Text(f"  {severity.value.upper()} ({len(group)})", style=_SEVERITY_STYLE[severity])
        )
        shown = group if limit is None else group[:limit]
        for finding in shown:
            loc = finding.location
            where = _clean(loc.path) + (f":{loc.start_line}" if loc.start_line else "")
            line = Text("    ")
            line.append(finding.rule_id, style="bold")
            line.append(f"  {where}")
            if finding.base_severity is not finding.severity:
                line.append(f"  (base {finding.base_severity.value})", style="dim")
            console.print(line)
            console.print(Padding(Text(_clean(finding.message), style="dim"), (0, 0, 0, 6)))
        if len(group) > len(shown):
            more = f"... and {len(group) - len(shown)} more (use --all)"
            console.print(Padding(Text(more, style="dim"), (0, 0, 0, 6)))


def render_terminal(
    report: AuditReport, console: Console, *, limit: int | None = DEFAULT_LIMIT
) -> None:
    """Print the full report. ``limit`` caps the checklist and each severity group of
    findings (``None`` shows everything)."""
    ascii_only = console.options.ascii_only
    bar_width = 20 if console.width >= 80 else 10
    c = report.classification

    head = Text()
    head.append(_clean(report.repo.name), style="bold")
    if report.repo.head_commit:
        head.append(f"  @ {report.repo.head_commit[:10]}", style="dim")
    head.append("\nStage: ")
    head.append(c.stage.value.upper(), style="bold green")
    head.append(f"  (rung {c.stage.order + 1} of {len(STAGE_ORDER)})")
    head.append(f"\nNext rung: {c.next_stage.value if c.next_stage else 'none, top of the ladder'}")
    head.append(f"\nOverall score: {report.overall_score:.1f} / 100")
    head.append(f"\n{c.rationale}", style="dim")
    console.print(Panel(head, title="rung", title_align="left", border_style="cyan"))

    _ladder(report, console, bar_width, ascii_only)
    _dimensions(report, console, bar_width, ascii_only)
    _checklist(report, console, limit)
    _findings(report, console, limit)

    errors = [r for r in report.rules if r.error]
    if errors:
        _heading(console, "Rule errors (skipped, not scored)")
        for result in errors:
            console.print(Text(f"  {result.rule_id}  {_clean(result.error or '')}", style="red"))

    s = report.summary
    counts = ", ".join(f"{s.counts_by_severity.get(sev, 0)} {sev.value}" for sev in Severity)
    console.print()
    console.print(Divider(style="dim"))
    console.print(
        Text(
            f"Findings: {counts} | suppressed: {s.suppressed} | rules: {s.rules_run} run "
            f"({s.rules_passed} passed, {s.rules_failed} failed, "
            f"{s.rules_not_applicable} n/a) | files: {s.files_scanned} | "
            f"commits: {s.commits_analyzed} | {s.duration_ms} ms"
        )
    )


def render_stages(console: Console) -> None:
    """Explain the four stages (``rung stages``)."""
    for number, info in enumerate(STAGE_INFO, start=1):
        console.print(Text(f"{number}. {info.title}", style="bold"))
        console.print(Padding(Text(info.summary), (0, 0, 0, 3)))
        for expectation in info.expectations:
            console.print(Padding(Text(f"- {expectation}", style="dim"), (0, 0, 0, 5)))
        console.print()


def render_rules(rules: Iterable[Rule], console: Console) -> None:
    """List rules grouped by stage (``rung rules``)."""
    ordered = sorted(rules, key=lambda r: (r.stage.order, r.id))
    stage: Stage | None = None
    for rule in ordered:
        if rule.stage is not stage:
            stage = rule.stage
            console.print(Text(f"\n{stage.value.upper()}", style="bold"))
        line = Text(f"  {rule.id}  ", style="bold")
        line.append(rule.severity.value.ljust(9), style=_SEVERITY_STYLE[rule.severity])
        line.append(_DIMENSION_LABEL[rule.dimension].ljust(18), style="dim")
        line.append(rule.title, style="default")
        console.print(line)
    console.print(Text(f"\n{len(ordered)} rules", style="dim"))
