# ruff: noqa: E501 - inline Dockerfile/compose fixtures read better on one line
from __future__ import annotations

from rung.models import Dimension, Outcome
from rung.probes import containers
from rung.probes._dockerfile import parse_dockerfile
from rung.registry import REGISTRY

GOOD = """# syntax=docker/dockerfile:1
ARG PY=3.12
FROM python:${PY}-slim AS builder
RUN pip install --no-cache-dir build \\
    # comment inside a continuation
    && python -m build
FROM python:3.12-slim
COPY --from=builder /dist /dist
HEALTHCHECK CMD python -c "print(1)"
USER 1000:1000
"""
P, F, NA = Outcome.passed, Outcome.failed, Outcome.not_applicable


def test_rule_metadata():
    rules = [r for r in REGISTRY if r.id.startswith("CTR")]
    assert [r.id for r in rules] == [f"CTR{i:03d}" for i in range(1, 11)]
    for r in rules:
        assert r.dimension is Dimension.containers
        assert r.description.strip() and r.remediation.strip()


def test_parser_handles_continuations_stages_and_heredocs():
    df = parse_dockerfile("Dockerfile", GOOD + "COPY <<EOF /x\nFROM nothing\nEOF\n")
    assert [s.image for s in df.stages] == ["python:${PY}-slim", "python:3.12-slim"]
    assert df.stages[0].name == "builder" and df.global_args[0].args == "PY=3.12"
    run = df.stages[0].last("RUN")
    assert run and (run.line, run.end_line) == (4, 6) and "&& python -m build" in run.args
    assert parse_dockerfile("D", "FROM --platform=$BUILDPLATFORM a:1 AS B\n").stages[0].platform


def test_good_repo_passes_and_empty_repo_is_na(make_repo):
    good = make_repo(
        {"Dockerfile": GOOD, ".dockerignore": ".git\n", "compose.yaml": "services: {}\n"}
    )
    empty = make_repo({"README.md": "FROM ubuntu"})
    for r in (r for r in REGISTRY if r.id.startswith("CTR")):
        assert r.run(good).outcome is P, r.id
        assert r.run(empty).outcome is (F if r.id == "CTR001" else NA), r.id


def test_ctr001_ignores_vendored_and_docs(make_repo):
    repo = make_repo(
        {
            "node_modules/x/Dockerfile": "FROM a",
            "Dockerfile.md": "x",
            "tests/fixtures/r/Dockerfile": "FROM a",
        }
    )
    res = containers.dockerfile_present(repo)
    assert res.outcome is F and res.hits[0].path == "Dockerfile"
    assert (
        containers.dockerfile_present(make_repo({"docker/api.dockerfile": "FROM a:1"})).outcome is P
    )


def test_ctr002(make_repo):
    bad = containers.dockerignore_present(make_repo({"svc/Dockerfile": "FROM a:1"}))
    assert bad.outcome is F and bad.hits[0].path == "svc/.dockerignore"
    ok = make_repo({"svc/Dockerfile": "FROM a:1", "svc/.dockerignore": ".git"})
    assert containers.dockerignore_present(ok).outcome is P


def test_ctr003(make_repo):
    bad = "FROM ubuntu\nFROM ghcr.io/org/app:latest AS b\nFROM localhost:5000/img\n"
    res = containers.base_images_pinned(make_repo({"Dockerfile": bad}))
    assert res.outcome is F and [h.line for h in res.hits] == [1, 2, 3]
    fine = "ARG BASE\nFROM node:20 AS builder\nFROM builder AS test\nFROM 0\nFROM scratch\nFROM ${BASE}\nFROM a@sha256:abc\n"
    assert containers.base_images_pinned(make_repo({"Dockerfile": fine})).outcome is P


def test_ctr004(make_repo):
    res = containers.non_root_user(
        make_repo({"Dockerfile": "FROM a:1\nUSER app\nFROM b:1\nRUN x\n"})
    )
    assert res.outcome is F and res.hits[0].line == 3
    assert (
        containers.non_root_user(
            make_repo({"Dockerfile": "FROM a:1\nUSER app\nUSER root\n"})
        ).outcome
        is F
    )
    for ok in (
        "FROM gcr.io/distroless/static:nonroot\n",
        "FROM a:1 AS base\nUSER app\nFROM base\n",
        "ARG B\nFROM $B\n",
    ):
        assert containers.non_root_user(make_repo({"Dockerfile": ok})).outcome is P, ok


def test_ctr005(make_repo):
    assert containers.orchestration_present(make_repo({"Dockerfile": "FROM a:1"})).outcome is F
    k8s = {"deploy/app.yaml": "apiVersion: apps/v1\nkind: Deployment\n", "Dockerfile": "FROM a:1"}
    assert containers.orchestration_present(make_repo(k8s)).outcome is P
    # a YAML file in deploy/ that is not a Kubernetes object does not count
    assert (
        containers.orchestration_present(
            make_repo({"deploy/vars.yml": "kind: x\n", "Dockerfile": "FROM a:1"})
        ).outcome
        is F
    )


def test_ctr006(make_repo):
    bad = """services:
  db:
    image: postgres
    privileged: true
  web:
    image: nginx:latest
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
    res = containers.compose_safe(make_repo({"docker-compose.yml": bad}))
    assert res.outcome is F and [h.line for h in res.hits] == [3, 4, 6, 7, 9]
    fine = """services:
  app:
    build: .
    image: myapp
    privileged: false
  db:
    image: postgres:${PG_VERSION}
  cache:
    image: redis:7.2 # not latest
"""
    assert containers.compose_safe(make_repo({"compose.yaml": fine})).outcome is P
    assert containers.compose_safe(make_repo({"compose.yaml": "services: [\n :"})).outcome is NA


def test_ctr007(make_repo):
    bad = "FROM a:1\nRUN apt-get update && \\\n  curl -fsSL https://x.test/i.sh | sudo bash\nADD https://x.test/f.tgz /f\n"
    res = containers.no_remote_code(make_repo({"Dockerfile": bad}))
    assert res.outcome is F and [(h.line, h.end_line) for h in res.hits] == [(2, 3), (4, 4)]
    fine = "FROM a:1\nRUN curl -fsSLo /t.tgz https://x.test/t && echo 'x  /t.tgz' | sha256sum -c\nADD --checksum=sha256:ab https://x.test/f /f\nADD local.tar /\n"
    assert containers.no_remote_code(make_repo({"Dockerfile": fine})).outcome is P


def test_ctr008(make_repo):
    res = containers.multi_stage(make_repo({"Dockerfile": "FROM a:1\nRUN echo FROM b\n"}))
    assert res.outcome is F and res.hits[0].line == 1
    two = {"Dockerfile": "FROM a:1\n", "api/Dockerfile": "FROM a:1 AS b\nFROM b\n"}
    assert containers.multi_stage(make_repo(two)).outcome is P


def test_ctr009(make_repo):
    assert (
        containers.health_declared(
            make_repo({"Dockerfile": "FROM a:1\nHEALTHCHECK NONE\n"})
        ).outcome
        is F
    )
    comp = {
        "Dockerfile": "FROM a:1\n",
        "compose.yml": "services:\n  a:\n    healthcheck:\n      test: x\n",
    }
    ok = containers.health_declared(make_repo(comp))
    assert ok.outcome is P and ok.evidence[0].start_line == 3
    k8s = {"k8s/d.yaml": "apiVersion: v1\nkind: Pod\nspec:\n  readinessProbe:\n    x: 1\n"}
    assert containers.health_declared(make_repo(k8s)).outcome is P


def test_ctr010_never_reveals_the_value(make_repo):
    fake = "fake-not-real-0123456789"
    bad = f'FROM a:1\nENV APP_ENV=prod DB_PASSWORD="{fake}"\nARG API_TOKEN={fake}\nENV SECRET_KEY {fake}\n'
    res = containers.no_baked_secrets(make_repo({"Dockerfile": bad}))
    assert res.outcome is F and [h.line for h in res.hits] == [2, 3, 4]
    assert "DB_PASSWORD" in res.hits[0].message
    assert fake not in res.summary and all(fake not in h.message for h in res.hits)
    fine = (
        "FROM a:1\nARG NPM_TOKEN\nARG GH_TOKEN=\nENV DB_PASSWORD=${DB_PASSWORD}\n"
        "ENV API_KEY=changeme PASSWORD_FILE=/run/secrets/pw TOKEN_TTL=3600\n"
        "ENV SECRET_KEY_BASE=<set-me> AWS_CREDENTIALS=/root/.aws/credentials\n"
    )
    assert containers.no_baked_secrets(make_repo({"Dockerfile": fine})).outcome is P
