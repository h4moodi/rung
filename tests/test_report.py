from __future__ import annotations

import json

import pytest
from rich.console import Console

from rung.config import BaselineEntry, Config
from rung.engine import run_audit
from rung.models import AuditReport, Check, Dimension, Hit, Severity, Stage
from rung.report import render_rules, render_stages, render_terminal, to_json, to_sarif
from tests.test_engine import FILES, build_registry


@pytest.fixture
def report(make_repo) -> AuditReport:
    reg = build_registry()

    @reg.rule(
        id="DOC009", title="Odd paths", dimension=Dimension.docs, stage=Stage.inception,
        severity=Severity.low, description="d", remediation="Rename it.",
    )  # fmt: skip
    def odd(repo):
        return Check.fail(
            "odd", [Hit("docs/my file#1.md", "odd \x1b[31mname[/red]", line=2, end_line=4)]
        )

    @reg.rule(
        id="DOC010", title="Crashes", dimension=Dimension.docs, stage=Stage.growth,
        severity=Severity.low, description="d", remediation="r",
    )  # fmt: skip
    def crash(repo):
        raise ValueError("kaput")

    root = make_repo(FILES).root
    first = run_audit(root, config=Config(), registry=reg)
    target = next(f for f in first.findings if f.location.path == "vendor/lib.py")
    entry = BaselineEntry(
        fingerprint=target.fingerprint, rule_id="SEC001", justification="vendored"
    )
    return run_audit(root, config=Config(baseline=(entry,)), registry=reg)


def test_json_round_trips_and_is_stable(report):
    text = to_json(report)
    assert text.endswith("}\n") and not text.endswith("\n\n")
    again = AuditReport.model_validate_json(text)
    assert again == report and to_json(again) == text
    data = json.loads(text)
    assert list(data)[:3] == ["tool", "repo", "classification"]
    assert list(data["summary"]["counts_by_severity"]) == [s.value for s in Severity]
    assert "\x1b" not in text  # control characters are escaped by the JSON encoder
    assert json.loads(to_json(report, indent=0)) == data


def test_sarif_structure(report):
    sarif = to_sarif(report)
    json.dumps(sarif)
    assert sarif["version"] == "2.1.0" and "sarif-2.1.0" in sarif["$schema"]
    (run,) = sarif["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "rung" and driver["version"] and driver["informationUri"]
    assert [r["id"] for r in driver["rules"]] == [r.rule_id for r in report.rules]
    assert run["properties"]["classification"]["stage"] == report.classification.stage.value

    for result in run["results"]:
        assert driver["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["partialFingerprints"]["rungFingerprint/v1"]
        assert result["message"]["text"]
    active = [r for r in run["results"] if not r["suppressions"]]
    assert len(active) == len(report.findings)
    expected = {"critical": "error", "high": "error", "medium": "warning"}
    for result, finding in zip(active, report.findings, strict=True):
        assert result["level"] == expected.get(finding.severity.value, "note")
        props = result["properties"]
        assert set(props) >= {"severity", "confidence", "stage", "priority"}
        assert props["severity"] == finding.severity.value
        physical = result["locations"][0]["physicalLocation"]
        assert ("region" in physical) == (finding.location.start_line is not None)

    by_rule = {r["ruleId"]: r for r in active}
    odd = by_rule["DOC009"]["locations"][0]["physicalLocation"]
    assert odd["artifactLocation"]["uri"] == "docs/my%20file%231.md"
    assert odd["region"] == {"startLine": 2, "endLine": 4}
    assert by_rule["CIC001"]["level"] == "note"  # down-ranked: beyond the next rung
    assert by_rule["CIC001"]["properties"]["priority"] == "later"
    assert by_rule["SEC001"]["properties"]["security-severity"] == "8.0"
    assert "security-severity" not in by_rule["TST001"]["properties"]


def test_sarif_rule_descriptors_and_suppressions(report):
    plain = to_sarif(report)["runs"][0]
    rules = {r["id"]: r for r in plain["tool"]["driver"]["rules"]}
    sec = rules["SEC001"]
    assert sec["name"] == "NoTODOMarkers" and sec["shortDescription"]["text"] == "No TODO markers"
    assert sec["defaultConfiguration"]["level"] == "error"
    assert sec["help"]["text"] == "Resolve or track the TODO."
    assert (
        sec["properties"]["dimension"] == "security" and sec["properties"]["stage"] == "inception"
    )
    assert "security" in sec["properties"]["tags"]
    assert sec["properties"]["security-severity"] == "8.0"
    assert "help" not in rules["DOC001"]  # passed, and no registry given

    (supp,) = [r for r in plain["results"] if r["suppressions"]]
    assert supp["suppressions"] == [{"kind": "external", "justification": "vendored"}]
    assert supp["ruleId"] == "SEC001"
    assert "region" not in supp["locations"][0]["physicalLocation"]

    rich_rules = to_sarif(report, registry=build_registry())["runs"][0]["tool"]["driver"]["rules"]
    enriched = {r["id"]: r for r in rich_rules}
    assert enriched["SEC001"]["fullDescription"]["text"] == "Markers pile up."
    assert "debt" in enriched["SEC001"]["properties"]["tags"]
    assert enriched["DOC001"]["help"]["text"] == "Add a README.md."


@pytest.mark.parametrize("width", [60, 120])
def test_terminal_renders_at_any_width(report, width):
    console = Console(record=True, no_color=True, width=width, force_terminal=False)
    render_terminal(report, console)
    text = console.export_text()
    flat = " ".join(text.split())
    assert report.classification.stage.value.upper() in flat
    assert "you are here" in flat and "Progression ladder" in flat
    for stage in Stage:
        assert stage.value in flat
    for item in report.checklist:
        assert item.title in flat and item.rule_id in flat
    for finding in report.findings:
        assert finding.rule_id in flat
    assert "src/app.py:3" in flat and "Findings:" in flat and "suppressed: 1" in flat
    assert "DOC010 ValueError: kaput" in flat
    assert "\x1b" not in text and "[/red]" in flat  # escapes stripped, markup left inert
    assert max(len(line) for line in text.splitlines()) <= width


def test_terminal_limit_truncates_and_none_shows_all(report):
    def render(limit):
        console = Console(record=True, no_color=True, width=100)
        render_terminal(report, console, limit=limit)
        return console.export_text()

    short, full = render(1), render(None)
    assert "more (use --all)" in short and "more (use --all)" not in full
    assert report.checklist[-1].title in full


def test_terminal_with_colour_and_clean_report(make_repo):
    clean = run_audit(make_repo(FILES).root, config=Config(disable={"SEC001", "TST001", "CIC001"}),
                      registry=build_registry())  # fmt: skip
    console = Console(record=True, force_terminal=True, width=80)
    render_terminal(clean, console)
    text = console.export_text()
    assert "MATURITY" in text and "No findings." in text and "Nothing to fix" in text


def test_stage_and_rule_listings():
    console = Console(record=True, no_color=True, width=80)
    render_stages(console)
    render_rules(build_registry(), console)
    text = console.export_text()
    assert "Inception" in text and "Maturity" in text
    assert "SEC001" in text and "5 rules" in text
