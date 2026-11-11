"""API tests: fake auditor, tmp sqlite db, no network."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from rung.api import sources
from rung.api.app import Settings, create_app
from rung.api.sources import SourcePolicy, checkout, clone_command, resolve_source
from rung.models import (
    AuditReport,
    Check,
    Classification,
    Confidence,
    Dimension,
    RepoInfo,
    Rule,
    Severity,
    Stage,
    Summary,
    ToolInfo,
)

HOSTS = ("github.com", "gitlab.com")


def fake_report(path: Path, source: str) -> AuditReport:
    return AuditReport(
        tool=ToolInfo(version="0.0.0"),
        repo=RepoInfo(name=path.name, source=source, is_git=False),
        classification=Classification(
            stage=Stage.stabilization, next_stage=Stage.growth, threshold=0.7, progress=[],
            rationale="fake",
        ),
        overall_score=62.5,
        dimensions=[],
        rules=[],
        findings=[],
        checklist=[],
        summary=Summary(
            counts_by_severity={Severity.high: 1, Severity.low: 2},
            rules_run=3, rules_passed=1, rules_failed=2, rules_not_applicable=0,
            files_scanned=4, commits_analyzed=0, suppressed=0, duration_ms=1,
        ),
    )  # fmt: skip


class FakeStage(BaseModel):
    stage: Stage
    title: str
    summary: str
    expectations: list[str]


RULE = Rule(
    id="ZZZ001", title="t", dimension=Dimension.docs, stage=Stage.growth,
    severity=Severity.low, confidence=Confidence.medium, description="d", remediation="r",
    run=lambda repo: Check.na("x"), weight=0.5,
)  # fmt: skip


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "root" / "proj").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    return tmp_path / "root"


@pytest.fixture
def client(tmp_path: Path, root: Path) -> TestClient:
    settings = Settings(
        db_path=tmp_path / "db" / "rung.sqlite3", local_root=root, allowed_hosts=HOSTS
    )
    app = create_app(
        settings,
        auditor=fake_report,
        sarif_renderer=lambda report: {"version": "2.1.0", "runs": [{"n": report.overall_score}]},
        rule_loader=lambda: [RULE],
        stage_loader=lambda: [
            FakeStage(stage=Stage.inception, title="I", summary="s", expectations=["e"])
        ],
    )
    return TestClient(app)


def test_health_rules_and_stages(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/api/rules").json() == {
        "items": [
            {
                "id": "ZZZ001", "title": "t", "dimension": "documentation", "stage": "growth",
                "severity": "low", "confidence": "medium", "weight": 0.5, "description": "d",
                "remediation": "r",
            }
        ]
    }  # fmt: skip
    assert client.get("/api/stages").json()["items"][0]["expectations"] == ["e"]


def test_audit_lifecycle(client, root):
    created = client.post("/api/audits", json={"source": "proj"})
    assert created.status_code == 201
    body = created.json()
    assert set(body) == {"id", "source", "created_at", "report"}
    assert body["source"] == "proj" and len(body["id"]) == 32
    assert body["report"]["classification"]["stage"] == "stabilization"
    assert str(root) not in created.text

    second = client.post("/api/audits", json={"source": str(root / "proj")}).json()
    listed = client.get("/api/audits").json()["items"]
    assert [a["id"] for a in listed] == [second["id"], body["id"]]
    assert listed[0] == {
        "id": second["id"], "source": "proj", "created_at": second["created_at"],
        "stage": "stabilization", "overall_score": 62.5,
        "counts_by_severity": {"high": 1, "low": 2},
    }  # fmt: skip
    assert [a["id"] for a in client.get("/api/audits?limit=1&offset=1").json()["items"]] == [
        body["id"]
    ]

    assert client.get(f"/api/audits/{body['id']}").json() == body
    sarif = client.get(f"/api/audits/{body['id']}/sarif").json()
    assert sarif == {"version": "2.1.0", "runs": [{"n": 62.5}]}
    assert client.delete(f"/api/audits/{body['id']}").status_code == 204
    assert client.get(f"/api/audits/{body['id']}").status_code == 404


@pytest.mark.parametrize("method,path", [
    ("get", "/api/audits/nope"), ("get", "/api/audits/nope/sarif"), ("delete", "/api/audits/nope"),
    ("get", "/api/audits/' OR 1=1 --"),
])  # fmt: skip
def test_unknown_audit_is_404(client, method, path):
    response = getattr(client, method)(path)
    assert response.status_code == 404
    assert response.json()["code"] == "audit_not_found"


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "offset=-1", "limit=abc"])
def test_list_validation(client, query):
    assert client.get(f"/api/audits?{query}").status_code == 422


@pytest.mark.parametrize("body", [{}, {"source": ""}, {"source": 5}, {"source": "x", "extra": 1}])
def test_body_validation_never_echoes_input(client, body):
    response = client.post("/api/audits", json=body)
    assert response.status_code == 422
    assert '"input"' not in response.text and '"ctx"' not in response.text


REJECTED = [
    ("ssh://git@github.com/o/r.git", 400),
    ("git@github.com:o/r.git", 400),
    ("file:///etc/passwd", 400),
    ("http://github.com/o/r", 400),
    ("git://github.com/o/r", 400),
    ("ext::sh -c 'id'", 400),  # no "://": handled as a (non-existent) local path, never by git
    ("--upload-pack=touch /tmp/pwned", 400),
    ("-oProxyCommand=id", 400),
    ("https://user:" + "hunter2" + "@github.com/o/r", 400),  # split so rung does not flag itself
    ("https://token@github.com/o/r", 400),
    ("https://evil.example/o/r", 403),
    ("https://github.com.evil.example/o/r", 403),
    ("https://github.com:8443/o/r", 400),
    ("https://github.com/o/r?x=1", 400),
    ("https://github.com/o/r#frag", 400),
    ("https://github.com/o", 400),
    ("https://github.com/o/r/extra", 400),
    ("https://github.com/../r", 400),
    ("https://github.com/o/..", 400),
    ("https://github.com/o/r%2e%2e", 400),
    ("https://github.com/o/r --upload-pack=x", 400),
    ("https://github.com/-o/r", 400),
    ("../outside", 403),
    ("proj/../../outside", 403),
    ("/etc", 403),
    ("missing", 400),
    ("a\x00b", 400),
]


@pytest.mark.parametrize(("source", "status"), REJECTED)
def test_rejected_sources(client, tmp_path, source, status):
    response = client.post("/api/audits", json={"source": source})
    assert response.status_code == status, response.text
    assert "hunter2" not in response.text and str(tmp_path) not in response.text
    assert client.get("/api/audits").json()["items"] == []


def test_symlink_out_of_root_is_rejected(client, root, tmp_path):
    (root / "link").symlink_to(tmp_path / "outside")
    assert client.post("/api/audits", json={"source": "link"}).status_code == 403


def test_local_paths_disabled_without_root(tmp_path):
    app = create_app(Settings(db_path=tmp_path / "rung.sqlite3"), auditor=fake_report)
    response = TestClient(app).post("/api/audits", json={"source": str(tmp_path)})
    assert response.status_code == 403


def test_auditor_crash_is_a_clean_500(tmp_path, root):
    def boom(path: Path, source: str) -> AuditReport:
        raise RuntimeError(f"secret detail in {path}")

    app = create_app(Settings(db_path=tmp_path / "rung.sqlite3", local_root=root), auditor=boom)
    response = TestClient(app).post("/api/audits", json={"source": "proj"})
    assert response.status_code == 500
    assert response.json() == {"detail": "the audit could not be completed", "code": "audit_failed"}


def test_cors_allows_only_configured_origin(client):
    ok = client.options("/api/audits", headers={
        "Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST"})  # fmt: skip
    assert ok.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "PUT" not in ok.headers["access-control-allow-methods"]
    bad = client.options("/api/audits", headers={
        "Origin": "http://evil.example", "Access-Control-Request-Method": "POST"})  # fmt: skip
    assert "access-control-allow-origin" not in bad.headers


def test_settings_from_env():
    s = Settings.from_env({
        "RUNG_DB": "/tmp/x.db", "RUNG_CORS_ORIGINS": "http://a, http://b",
        "RUNG_ALLOWED_HOSTS": "GitHub.com", "RUNG_LOCAL_ROOT": "/srv", "RUNG_CLONE_TIMEOUT": "5",
        "RUNG_MAX_REPO_MB": "1",
    })  # fmt: skip
    assert s.cors_origins == ("http://a", "http://b") and s.allowed_hosts == ("github.com",)
    assert s.source_policy() == SourcePolicy(("github.com",), Path("/srv"), 5, 1024 * 1024)
    default = Settings.from_env({})
    assert default.local_root is None and default.clone_timeout == 120
    assert "codeberg.org" in default.allowed_hosts and default.db_path == Path("rung.sqlite3")


# ------------------------------------------------------------------ remote sources


@pytest.mark.parametrize(("source", "url"), [
    ("https://github.com/acme/widget", "https://github.com/acme/widget"),
    ("https://GitHub.com/acme/widget.git", "https://github.com/acme/widget"),
    ("HTTPS://gitlab.com/acme/.github/", "https://gitlab.com/acme/.github"),
])  # fmt: skip
def test_remote_urls_are_normalised(source, url):
    resolved = resolve_source(source, SourcePolicy(HOSTS))
    assert (resolved.url, resolved.display, resolved.path) == (url, url, None)


def test_clone_command_is_hardened():
    cmd = clone_command("https://github.com/o/r", Path("/tmp/d"))
    assert cmd[-3:] == ["--", "https://github.com/o/r", "/tmp/d"]
    for option in ("protocol.ext.allow=never", "protocol.file.allow=never",
                   "core.hooksPath=/dev/null", "credential.helper="):  # fmt: skip
        assert option in cmd
    assert "--single-branch" in cmd and "--no-recurse-submodules" in cmd
    assert not any(a.startswith("--depth") or a == "--no-tags" for a in cmd)


def _fake_git(returncode: int = 0, payload: int = 10, seen: list | None = None):
    def run(cmd, **kwargs):
        if seen is not None:
            seen.append((cmd, kwargs))
        dest = Path(cmd[-1])
        dest.mkdir()
        (dest / "f.bin").write_bytes(b"x" * payload)
        return subprocess.CompletedProcess(cmd, returncode, b"", b"fatal: secret-ish stderr")

    return run


def test_checkout_clones_then_always_cleans_up():
    policy = SourcePolicy(HOSTS, clone_timeout=7)
    resolved = resolve_source("https://github.com/o/r", policy)
    seen: list = []
    with checkout(resolved, policy, runner=_fake_git(seen=seen)) as path:
        assert (path / "f.bin").is_file()
        workdir = path.parent
    assert not workdir.exists()
    cmd, kwargs = seen[0]
    assert cmd == clone_command("https://github.com/o/r", path)
    assert kwargs["timeout"] == 7 and kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"


def _fails(runner, policy, error):
    resolved = resolve_source("https://github.com/o/r", policy)
    made: list[Path] = []
    real = sources.tempfile.mkdtemp

    def tracking(**kwargs):
        made.append(Path(real(**kwargs)))
        return str(made[-1])

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sources.tempfile, "mkdtemp", tracking)
        with pytest.raises(error) as info, checkout(resolved, policy, runner=runner):
            pass
    assert made and not made[0].exists()
    assert "stderr" not in info.value.message
    return info.value


def test_clone_failures_map_to_clean_errors():
    def timeout(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1)

    def no_git(cmd, **kwargs):
        raise FileNotFoundError("git")

    assert (
        _fails(_fake_git(returncode=128), SourcePolicy(HOSTS), sources.CloneFailed).status_code
        == 502
    )
    assert _fails(timeout, SourcePolicy(HOSTS), sources.CloneTimeout).status_code == 504
    assert _fails(no_git, SourcePolicy(HOSTS), sources.CloneFailed).status_code == 502
    small = SourcePolicy(HOSTS, max_repo_bytes=5)
    assert _fails(_fake_git(payload=6), small, sources.RepoTooLarge).status_code == 413
