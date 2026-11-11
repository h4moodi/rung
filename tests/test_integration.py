"""Full pipeline with the real built-in rules on two fixture repositories.

Only structural invariants are asserted, so the test holds whichever rules exist.
"""

from __future__ import annotations

import importlib
import json
import pkgutil

import pytest

from rung.config import Config
from rung.engine import run_audit
from rung.models import DIMENSION_ORDER, STAGE_ORDER, AuditReport
from rung.registry import Registry
from rung.report import to_json, to_sarif
from tests.test_engine import tree_digest, zeroed

COMMITS = [
    {"message": "fix: handle upstream timeouts", "files": {"src/service/retry.py": "RETRIES = 3\n"},
     "date": "2026-01-20T09:00:00+00:00", "author": ("Second Dev", "second@example.com")},
    {"message": "docs: describe releases", "files": {"docs/releasing.md": "# Releasing\n"},
     "date": "2026-02-02T09:00:00+00:00", "tag": "v1.2.0"},
]  # fmt: skip


@pytest.fixture(scope="module")
def registry() -> Registry:
    import rung.probes as probes
    from rung.registry import REGISTRY

    for mod in sorted(pkgutil.iter_modules(probes.__path__), key=lambda m: m.name):
        if mod.name.startswith("_"):
            continue
        name = f"{probes.__name__}.{mod.name}"
        try:
            importlib.import_module(name)
        except Exception as exc:  # name the broken probe module for the integrator
            pytest.fail(f"probe module {name} failed to import: {type(exc).__name__}: {exc}")
    if len(REGISTRY) == 0:
        pytest.fail("no built-in rules are registered: rung.probes has no probe modules yet")
    return REGISTRY


@pytest.fixture
def reports(make_repo, registry) -> tuple[AuditReport, AuditReport]:
    bare = make_repo(fixture="core_bare_mvp", message="init")
    mature = make_repo(fixture="core_mature_service", commits=COMMITS)
    return (
        run_audit(bare.root, config=Config(), registry=registry),
        run_audit(mature.root, config=Config(), registry=registry),
    )


def test_reports_validate_and_are_internally_consistent(reports, registry):
    known = {rule.id for rule in registry}
    for report in reports:
        AuditReport.model_validate_json(to_json(report))
        assert {r.rule_id for r in report.rules} == known
        assert [d.dimension for d in report.dimensions] == list(DIMENSION_ORDER)
        assert [p.stage for p in report.classification.progress] == list(STAGE_ORDER)
        assert sum(report.summary.counts_by_severity.values()) == len(report.findings)
        assert len({f.fingerprint for f in report.findings}) == len(report.findings)
        failed = {r.rule_id for r in report.rules if r.outcome.value == "failed"}
        assert {i.rule_id for i in report.checklist} == failed
        for finding in report.findings:
            assert finding.location.path.strip() and finding.rule_id in known
            assert finding.message.strip() and finding.rule_id in failed
        crashed = {r.rule_id: r.error for r in report.rules if r.error}
        assert not crashed, f"built-in rules crashed: {crashed}"


def test_mature_fixture_outranks_the_bare_one(reports):
    bare, mature = reports
    assert mature.overall_score > bare.overall_score
    assert mature.classification.stage.order >= bare.classification.stage.order


def test_runs_are_byte_identical_and_read_only(make_repo, registry):
    repo = make_repo(fixture="core_mature_service", commits=COMMITS)
    before = tree_digest(repo.root)
    first = run_audit(repo.root, config=Config(), registry=registry)
    second = run_audit(repo.root, config=Config(), registry=registry)
    assert zeroed(first) == zeroed(second)
    assert tree_digest(repo.root) == before


def test_sarif_renders_for_real_rules(reports, registry):
    for report in reports:
        sarif = to_sarif(report, registry=registry)
        json.dumps(sarif)
        run = sarif["runs"][0]
        ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        assert len(run["results"]) == len(report.findings)
        assert all(ids[r["ruleIndex"]] == r["ruleId"] for r in run["results"])
