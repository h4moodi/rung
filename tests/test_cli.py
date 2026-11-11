from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

import rung.cli as cli
from rung import __version__
from tests.test_engine import FILES, build_registry, tree_digest

runner = CliRunner()


@pytest.fixture(autouse=True)
def fake_registry(monkeypatch):
    monkeypatch.setattr(cli, "_load_registry", build_registry)
    monkeypatch.delenv("RUNG_DEBUG", raising=False)


@pytest.fixture
def repo(make_repo):
    return make_repo(FILES).root


def run(*args):
    return runner.invoke(cli.app, [str(a) for a in args])


def test_version():
    result = run("--version")
    assert result.exit_code == 0 and result.stdout.strip() == f"rung {__version__}"


def test_audit_terminal_exits_1_on_high_findings(repo):
    before = tree_digest(repo)
    result = run("audit", repo, "--no-color")
    assert result.exit_code == 1
    assert "INCEPTION" in result.stdout and "SEC001" in result.stdout
    assert tree_digest(repo) == before


def test_fail_on_controls_the_exit_code(repo):
    assert run("audit", repo, "--format", "json", "--fail-on", "critical").exit_code == 0
    assert run("audit", repo, "--format", "json", "--fail-on", "info").exit_code == 1
    assert run("audit", repo, "--fail-on", "nonsense").exit_code == 2


def test_json_to_stdout_is_only_json(repo):
    result = run("audit", repo, "--format", "json", "--fail-on", "critical")
    data = json.loads(result.stdout)
    assert data["classification"]["stage"] == "inception" and result.stdout.endswith("}\n")


def test_sarif_to_stdout(repo):
    result = run("audit", repo, "--format", "sarif")
    sarif = json.loads(result.stdout)
    assert result.exit_code == 1 and sarif["version"] == "2.1.0"
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["fullDescription"]["text"] == "Supply chain."


def test_config_file_and_fail_on_override(repo, tmp_path):
    cfg = tmp_path / "ci.toml"
    cfg.write_text('[rung]\nfail_on = "critical"\n[rules]\ndisable = ["CIC001"]\n')
    result = run("audit", repo, "--format", "json", "--config", cfg)
    assert result.exit_code == 0
    assert "CIC001" not in [r["rule_id"] for r in json.loads(result.stdout)["rules"]]
    assert (
        run("audit", repo, "--format", "json", "--config", cfg, "--fail-on", "high").exit_code == 1
    )


def test_output_file_and_in_repo_guard(repo, tmp_path):
    out = tmp_path / "out" / "report.json"
    result = run("audit", repo, "--format", "json", "--output", out, "--fail-on", "critical")
    assert result.exit_code == 0 and result.stdout == ""
    assert json.loads(out.read_text())["tool"]["name"] == "rung"

    text_out = tmp_path / "report.txt"
    assert run("audit", repo, "--output", text_out).exit_code == 1
    assert "Progression ladder" in text_out.read_text() and "\x1b" not in text_out.read_text()

    before = tree_digest(repo)
    blocked = run("audit", repo, "--format", "json", "--output", repo / "sub" / "r.json")
    assert blocked.exit_code == 2 and "--allow-write-in-repo" in blocked.stderr
    assert blocked.stdout == "" and tree_digest(repo) == before

    allowed = run(
        "audit", repo, "--format", "json", "--output", repo / "r.json",
        "--allow-write-in-repo", "--fail-on", "critical",
    )  # fmt: skip
    assert allowed.exit_code == 0 and (repo / "r.json").is_file()


def test_errors_exit_2_with_one_line_and_no_traceback(repo, tmp_path, monkeypatch):
    missing = run("audit", tmp_path / "nope")
    assert missing.exit_code == 2 and missing.stderr.startswith("rung: error: not a directory")

    (repo / "rung.toml").write_text('[rules]\ndisable = ["NOPE999"]\n')
    unknown = run("audit", repo)
    assert unknown.exit_code == 2 and "unknown rule id 'NOPE999'" in unknown.stderr
    (repo / "rung.toml").write_text('[rung]\nfail_on = "bogus"\n')
    assert run("audit", repo).exit_code == 2

    def boom(*args, **kwargs):
        raise RuntimeError("engine fell over")

    (repo / "rung.toml").unlink()
    monkeypatch.setattr(cli, "run_audit", boom)
    crashed = run("audit", repo)
    assert crashed.exit_code == 2 and crashed.stdout == ""
    assert crashed.stderr.strip() == "rung: error: RuntimeError: engine fell over"
    monkeypatch.setenv("RUNG_DEBUG", "1")
    assert "Traceback" in run("audit", repo).stderr


def test_rules_and_stages(repo):
    listed = run("rules", "--format", "json")
    data = json.loads(listed.stdout)
    assert listed.exit_code == 0
    assert [r["id"] for r in data] == ["CIC001", "CTR001", "DOC001", "SEC001", "TST001"]
    assert data[3]["stage"] == "inception" and data[3]["tags"] == ["debt"]
    assert set(data[0]) >= {"title", "dimension", "severity", "description", "remediation"}
    text = run("rules", "--no-color")
    assert text.exit_code == 0 and "SEC001" in text.stdout and "MATURITY" in text.stdout
    stages = run("stages", "--no-color")
    assert stages.exit_code == 0 and "Stabilization" in stages.stdout


def test_baseline_workflow(repo, tmp_path):
    out = tmp_path / "rung-baseline.json"
    assert run("baseline", repo, "--output", out, "--justification", "  ").exit_code == 2
    assert run("baseline", repo, "--output", out).exit_code == 2
    assert not out.exists()
    assert run("baseline", repo, "--output", repo / "b.json", "--justification", "x").exit_code == 2

    made = run("baseline", repo, "--output", out, "--justification", "accepted for the pilot")
    assert made.exit_code == 0 and "4 finding(s)" in made.stdout
    entries = json.loads(out.read_text())
    assert len(entries) == 4
    assert all(e["justification"] == "accepted for the pilot" and e["path"] for e in entries)

    cfg = tmp_path / "rung.toml"
    cfg.write_text('[baseline]\nfile = "rung-baseline.json"\n')
    audited = run("audit", repo, "--format", "json", "--config", cfg)
    report = json.loads(audited.stdout)
    assert audited.exit_code == 0 and report["findings"] == [] and len(report["suppressed"]) == 4

    # Regenerating keeps earlier justifications.
    again = tmp_path / "again.json"
    run("baseline", repo, "--output", again, "--justification", "new", "--config", cfg)
    assert json.loads(again.read_text()) == entries


def test_serve_without_api_extra(monkeypatch):
    monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
    result = run("serve")
    assert result.exit_code == 2 and "rung[api]" in result.stderr


def test_serve_runs_uvicorn_with_the_app_factory(monkeypatch):
    uvicorn = pytest.importorskip("uvicorn")
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: calls.append((a, k)))
    assert run("serve", "--port", "9001").exit_code == 0
    assert calls == [
        (("rung.api.app:create_app",), {"factory": True, "host": "127.0.0.1", "port": 9001})
    ]
