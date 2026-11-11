from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from rung.config import BaselineEntry, Config, ConfigError
from rung.engine import has_blocking_findings, run_audit
from rung.models import (
    DIMENSION_ORDER,
    AuditReport,
    Check,
    Confidence,
    Dimension,
    Hit,
    Outcome,
    Severity,
    Stage,
)
from rung.registry import Registry

FILES = {
    "README.md": "# demo\n",
    "src/app.py": "import os\n\nvalue = 1  # TODO: tidy\n",
    "vendor/lib.py": "x = 2  # TODO: upstream\n",
}


def build_registry() -> Registry:
    """A private registry of fake rules covering every stage and outcome."""
    reg = Registry()

    @reg.rule(
        id="DOC001", title="README present", dimension=Dimension.docs, stage=Stage.inception,
        severity=Severity.medium, description="Entry point.", remediation="Add a README.md.",
    )  # fmt: skip
    def readme(repo):
        found = repo.find_named("README.md", root_only=True)
        return (
            Check.ok("README found", evidence=found)
            if found
            else Check.fail("No README at the repository root", at="README.md")
        )

    @reg.rule(
        id="SEC001", title="No TODO markers", dimension=Dimension.security,
        stage=Stage.inception, severity=Severity.high, weight=2.0, tags=("debt",),
        description="Markers pile up.", remediation="Resolve or track the TODO.",
    )  # fmt: skip
    def todo(repo):
        hits = [Hit(m.path, "TODO marker left in code", line=m.line) for m in repo.grep("TODO")]
        return Check.fail(f"{len(hits)} TODO marker(s)", hits) if hits else Check.ok("clean")

    @reg.rule(
        id="TST001", title="Tests exist", dimension=Dimension.tests, stage=Stage.stabilization,
        severity=Severity.high, description="Verify changes.", remediation="Add a tests/ dir.",
    )  # fmt: skip
    def tests(repo):
        return (
            Check.ok("tests found")
            if repo.has_dir("tests")
            else Check.fail("No tests directory", at="tests")
        )

    @reg.rule(
        id="CIC001", title="Actions pinned", dimension=Dimension.cicd, stage=Stage.maturity,
        severity=Severity.high, confidence=Confidence.medium,
        description="Supply chain.", remediation="Pin actions to a commit SHA.",
    )  # fmt: skip
    def pinned(repo):
        return Check.fail("Workflows are not pinned", at=".github/workflows")

    @reg.rule(
        id="CTR001", title="Dockerfile hardened", dimension=Dimension.containers,
        stage=Stage.growth, severity=Severity.medium,
        description="Containers.", remediation="Harden the Dockerfile.",
    )  # fmt: skip
    def docker(repo):
        return Check.na("No Dockerfile")

    return reg


def zeroed(report: AuditReport) -> str:
    data = report.model_dump(mode="json")
    data["summary"]["duration_ms"] = 0
    return json.dumps(data, sort_keys=True)


def tree_digest(root: Path) -> str:
    """Hash every path under ``root`` (``.git`` included): names, types, mtimes, contents."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
        stat = path.lstat()
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(f"{stat.st_mode}:{stat.st_mtime_ns}:{stat.st_size}".encode())
        if path.is_file() and not path.is_symlink():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def by_rule(report: AuditReport) -> dict[str, list]:
    out: dict[str, list] = {}
    for finding in report.findings:
        out.setdefault(finding.rule_id, []).append(finding)
    return out


# ------------------------------------------------------------------------- happy path


def test_report_shape_and_repo_info(make_repo):
    repo = make_repo(FILES)
    report = run_audit(repo.root, config=Config(), registry=build_registry())
    AuditReport.model_validate(report.model_dump())

    assert report.tool.name == "rung" and report.tool.version
    assert report.repo.name == repo.root.name and report.repo.source == str(repo.root)
    assert report.repo.is_git and report.repo.head_commit == repo.head
    assert report.repo.branch == "main" and report.repo.head_date.startswith("2026-01-15")
    assert [r.rule_id for r in report.rules] == ["CIC001", "CTR001", "DOC001", "SEC001", "TST001"]
    assert [d.dimension for d in report.dimensions] == list(DIMENSION_ORDER)

    s = report.summary
    assert (s.rules_run, s.rules_passed, s.rules_failed, s.rules_not_applicable) == (5, 1, 3, 1)
    assert s.files_scanned == 3 and s.commits_analyzed == 1 and s.suppressed == 0
    assert list(s.counts_by_severity) == list(Severity)
    assert sum(s.counts_by_severity.values()) == len(report.findings) == 4
    assert sum(r.finding_count for r in report.rules) == len(report.findings)


def test_classification_drives_stage_aware_severity(make_repo):
    report = run_audit(make_repo(FILES).root, config=Config(), registry=build_registry())
    # inception: DOC001 passes (1) but SEC001 fails (2) -> 33%, so the floor applies.
    assert report.classification.stage is Stage.inception
    assert report.classification.progress[0].met is False
    found = by_rule(report)
    assert {f.severity for f in found["SEC001"]} == {Severity.high}  # overdue: unchanged
    assert found["TST001"][0].severity is Severity.high  # next rung: unchanged
    later = found["CIC001"][0]
    assert later.severity is Severity.info and later.base_severity is Severity.high
    assert later.confidence is Confidence.medium
    assert [(i.rule_id, i.priority) for i in report.checklist] == [
        ("SEC001", "overdue"), ("TST001", "next"), ("CIC001", "later"),
    ]  # fmt: skip
    assert report.summary.counts_by_severity[Severity.high] == 3
    assert report.summary.counts_by_severity[Severity.info] == 1


def test_findings_are_sorted_by_severity_rule_path_line(make_repo):
    report = run_audit(make_repo(FILES).root, config=Config(), registry=build_registry())
    keys = [
        (-f.severity.rank, f.rule_id, f.location.path, f.location.start_line or 0)
        for f in report.findings
    ]
    assert keys == sorted(keys)
    assert [(f.rule_id, f.location.path, f.location.start_line) for f in report.findings] == [
        ("SEC001", "src/app.py", 3),
        ("SEC001", "vendor/lib.py", 1),
        ("TST001", "tests", None),
        ("CIC001", ".github/workflows", None),
    ]


def test_non_git_directory_and_source_naming(make_repo):
    repo = make_repo(FILES, git=False)
    report = run_audit(
        repo.root, config=Config(), registry=build_registry(),
        source="https://github.com/example/demo-service.git",
    )  # fmt: skip
    assert report.repo.name == "demo-service"
    assert report.repo.source == "https://github.com/example/demo-service.git"
    assert not report.repo.is_git and report.repo.head_commit is None
    assert report.summary.commits_analyzed == 0 and report.summary.files_scanned == 3


def test_config_is_loaded_from_the_repo_when_not_given(make_repo):
    repo = make_repo({**FILES, "rung.toml": '[rules]\ndisable = ["CIC001", "TST001"]\n'})
    report = run_audit(repo.root, registry=build_registry())
    assert [r.rule_id for r in report.rules] == ["CTR001", "DOC001", "SEC001"]


def test_bad_path_raises(tmp_path):
    with pytest.raises(NotADirectoryError):
        run_audit(tmp_path / "missing", config=Config(), registry=build_registry())


# -------------------------------------------------------------------- crash isolation


def test_a_crashing_rule_is_isolated_and_reported_without_traceback(make_repo):
    reg = build_registry()

    @reg.rule(
        id="DOC002", title="Explodes", dimension=Dimension.docs, stage=Stage.inception,
        severity=Severity.low, description="d", remediation="r",
    )  # fmt: skip
    def explode(repo):
        raise RuntimeError("boom\nsecond line " + "x" * 500)

    @reg.rule(
        id="DOC003", title="Returns nothing", dimension=Dimension.docs, stage=Stage.inception,
        severity=Severity.low, description="d", remediation="r",
    )  # fmt: skip
    def nothing(repo):
        return None

    report = run_audit(make_repo(FILES).root, config=Config(), registry=reg)
    results = {r.rule_id: r for r in report.rules}
    crashed = results["DOC002"]
    assert crashed.outcome is Outcome.not_applicable
    assert crashed.error.startswith("RuntimeError: boom second line xxx")
    assert "\n" not in crashed.error and "Traceback" not in crashed.error
    assert len(crashed.error) <= len("RuntimeError: ") + 200
    assert results["DOC003"].error == "RuleContractError: returned NoneType, expected Check"
    # The other rules still ran and the crashed ones do not affect any score.
    assert results["SEC001"].outcome is Outcome.failed and results["DOC001"].error is None
    clean = run_audit(make_repo(FILES).root, config=Config(), registry=build_registry())
    assert report.overall_score == clean.overall_score
    assert report.summary.rules_not_applicable == clean.summary.rules_not_applicable + 2


def test_hits_without_a_path_are_rejected_as_rule_errors(make_repo):
    reg = Registry()

    @reg.rule(
        id="DOC001", title="t", dimension=Dimension.docs, stage=Stage.inception,
        severity=Severity.low, description="d", remediation="r",
    )  # fmt: skip
    def pathless(repo):
        return Check.fail("bad", [Hit(path=" ", message="nowhere")])

    report = run_audit(make_repo(FILES).root, config=Config(), registry=reg)
    assert report.findings == [] and report.rules[0].outcome is Outcome.not_applicable
    assert "empty path" in report.rules[0].error


# ------------------------------------------------------------------------------ config


def test_disabled_rules_do_not_run(make_repo):
    cfg = Config(disable={"SEC001", "CIC001"})
    report = run_audit(make_repo(FILES).root, config=cfg, registry=build_registry())
    assert [r.rule_id for r in report.rules] == ["CTR001", "DOC001", "TST001"]
    assert "SEC001" not in by_rule(report) and report.summary.rules_run == 3
    assert report.classification.stage is Stage.inception  # inception met, stabilization not
    assert report.classification.progress[0].met


def test_severity_override_replaces_the_rule_default(make_repo):
    cfg = Config(severity_overrides={"SEC001": Severity.low, "TST001": Severity.critical})
    report = run_audit(make_repo(FILES).root, config=cfg, registry=build_registry())
    found = by_rule(report)
    assert {f.severity for f in found["SEC001"]} == {Severity.low}
    assert {f.base_severity for f in found["SEC001"]} == {Severity.low}
    assert found["TST001"][0].severity is Severity.critical
    results = {r.rule_id: r for r in report.rules}
    assert results["SEC001"].severity is Severity.low
    assert results["DOC001"].severity is Severity.medium


def test_hit_level_severity_and_how_overrides_cap_it(make_repo):
    reg = Registry()

    @reg.rule(
        id="SEC002", title="Mixed", dimension=Dimension.security, stage=Stage.inception,
        severity=Severity.medium, description="d", remediation="r",
    )  # fmt: skip
    def mixed(repo):
        return Check.fail(
            "three hits",
            [
                Hit("a.txt", "default"),
                Hit("b.txt", "escalated", severity=Severity.critical, confidence=Confidence.low),
                Hit("c.txt", "downgraded", severity=Severity.info),
            ],
        )

    root = make_repo(FILES).root
    plain = {f.location.path: f for f in run_audit(root, config=Config(), registry=reg).findings}
    assert plain["a.txt"].severity is Severity.medium
    assert plain["b.txt"].severity is Severity.critical
    assert plain["b.txt"].confidence is Confidence.low
    assert plain["a.txt"].confidence is Confidence.high
    assert plain["c.txt"].severity is Severity.info

    cfg = Config(severity_overrides={"SEC002": Severity.low})
    capped = {
        f.location.path: f.severity for f in run_audit(root, config=cfg, registry=reg).findings
    }
    assert capped == {"a.txt": Severity.low, "b.txt": Severity.low, "c.txt": Severity.info}


def test_ignore_paths_hide_files_from_rules(make_repo):
    cfg = Config(ignore_paths=("vendor/**",))
    report = run_audit(make_repo(FILES).root, config=cfg, registry=build_registry())
    assert [f.location.path for f in by_rule(report)["SEC001"]] == ["src/app.py"]
    assert report.summary.files_scanned == 2


@pytest.mark.parametrize(
    "cfg",
    [
        Config(disable={"NOPE999"}),
        Config(severity_overrides={"NOPE999": Severity.low}),
        Config(baseline=(BaselineEntry(fingerprint="f", rule_id="NOPE999", justification="j"),)),
    ],
)
def test_unknown_rule_ids_are_a_config_error(make_repo, cfg):
    with pytest.raises(ConfigError, match="unknown rule id 'NOPE999'"):
        run_audit(make_repo(FILES).root, config=cfg, registry=build_registry())


# ---------------------------------------------------------------------------- baseline


def test_baseline_suppresses_findings_without_awarding_credit(make_repo):
    root = make_repo(FILES).root
    before = run_audit(root, config=Config(), registry=build_registry())
    target = next(f for f in before.findings if f.location.path == "vendor/lib.py")
    cfg = Config(
        baseline=(
            BaselineEntry(
                fingerprint=target.fingerprint, rule_id="SEC001", justification="vendored code"
            ),
            BaselineEntry(fingerprint="stale-entry", rule_id="DOC001", justification="gone"),
        )
    )
    after = run_audit(root, config=cfg, registry=build_registry())

    assert [f.fingerprint for f in after.findings] == [
        f.fingerprint for f in before.findings if f is not target
    ]
    assert len(after.suppressed) == 1 and after.summary.suppressed == 1
    supp = after.suppressed[0]
    assert (supp.fingerprint, supp.rule_id, supp.path, supp.justification) == (
        target.fingerprint, "SEC001", "vendor/lib.py", "vendored code",
    )  # fmt: skip
    assert after.summary.counts_by_severity[Severity.high] == 2
    # Suppression hides noise; it does not make the rule pass.
    result = next(r for r in after.rules if r.rule_id == "SEC001")
    assert result.outcome is Outcome.failed and result.finding_count == 1
    assert after.overall_score == before.overall_score
    assert after.classification == before.classification


def test_fully_suppressed_rule_stays_on_the_checklist(make_repo):
    root = make_repo(FILES).root
    before = run_audit(root, config=Config(), registry=build_registry())
    target = next(f for f in before.findings if f.rule_id == "TST001")
    entry = BaselineEntry(fingerprint=target.fingerprint, rule_id="TST001", justification="soon")
    after = run_audit(root, config=Config(baseline=(entry,)), registry=build_registry())
    item = next(i for i in after.checklist if i.rule_id == "TST001")
    assert item.finding_count == 0 and item.remediation == "Add a tests/ dir."
    assert not has_blocking_findings(after, Severity.critical)


def test_baseline_entry_must_match_the_rule_id_too(make_repo):
    root = make_repo(FILES).root
    target = run_audit(root, config=Config(), registry=build_registry()).findings[0]
    wrong = BaselineEntry(fingerprint=target.fingerprint, rule_id="DOC001", justification="j")
    report = run_audit(root, config=Config(baseline=(wrong,)), registry=build_registry())
    assert report.suppressed == []


# ------------------------------------------------------------- determinism/fingerprints


def test_two_runs_are_identical_except_duration(make_repo):
    root = make_repo(FILES).root
    first = run_audit(root, config=Config(), registry=build_registry())
    second = run_audit(root, config=Config(), registry=build_registry())
    assert zeroed(first) == zeroed(second)


def test_fingerprints_survive_unrelated_lines_added_above(make_repo):
    before = run_audit(make_repo(FILES).root, config=Config(), registry=build_registry())
    shifted = {**FILES, "src/app.py": "# header\n# more\n" + FILES["src/app.py"]}
    after = run_audit(make_repo(shifted).root, config=Config(), registry=build_registry())

    def app_finding(report):
        return next(f for f in report.findings if f.location.path == "src/app.py")

    assert app_finding(before).location.start_line == 3
    assert app_finding(after).location.start_line == 5
    assert app_finding(before).fingerprint == app_finding(after).fingerprint
    assert {f.fingerprint for f in before.findings} == {f.fingerprint for f in after.findings}


def test_identical_lines_get_distinct_stable_fingerprints(make_repo):
    files = {"a.py": "x = 1  # TODO\ny = 2\nx = 1  # TODO\n"}
    first = run_audit(make_repo(files).root, config=Config(), registry=build_registry())
    second = run_audit(make_repo(files).root, config=Config(), registry=build_registry())
    prints = [f.fingerprint for f in first.findings if f.rule_id == "SEC001"]
    assert len(prints) == 2 and len(set(prints)) == 2
    assert prints == [f.fingerprint for f in second.findings if f.rule_id == "SEC001"]
    assert len({f.fingerprint for f in first.findings}) == len(first.findings)


def test_missing_artifact_fingerprint_uses_the_message(make_repo):
    report = run_audit(make_repo(FILES).root, config=Config(), registry=build_registry())
    from rung.models import fingerprint

    tst = next(f for f in report.findings if f.rule_id == "TST001")
    assert tst.fingerprint == fingerprint("TST001", "tests", "No tests directory")
    sec = next(f for f in report.findings if f.location.path == "src/app.py")
    assert sec.fingerprint == fingerprint("SEC001", "src/app.py", "value = 1  # TODO: tidy")


# --------------------------------------------------------------------------- read-only


@pytest.mark.parametrize("git", [True, False])
def test_audit_never_writes_to_the_audited_tree(make_repo, git):
    repo = make_repo({**FILES, "rung.toml": '[rung]\nfail_on = "low"\n'}, git=git)
    before = tree_digest(repo.root)
    run_audit(repo.root, registry=build_registry())
    run_audit(repo.root, config=Config(ignore_paths=("vendor/**",)), registry=build_registry())
    assert tree_digest(repo.root) == before


# ---------------------------------------------------------------------------- exit gate


def test_has_blocking_findings_uses_stage_adjusted_severity(make_repo):
    cfg = Config(disable={"SEC001"}, severity_overrides={"TST001": Severity.low})
    report = run_audit(make_repo(FILES).root, config=cfg, registry=build_registry())
    # CIC001 (maturity, base high) sits two rungs above the classified stage -> info.
    assert [(f.rule_id, f.severity) for f in report.findings] == [
        ("TST001", Severity.low),
        ("CIC001", Severity.info),
    ]
    assert not has_blocking_findings(report, Severity.medium)
    assert has_blocking_findings(report, Severity.low)
