from __future__ import annotations

from rung.models import Dimension, Outcome
from rung.probes import cicd
from rung.registry import REGISTRY

WF = ".github/workflows/ci.yml"
SHA = "a" * 40

GOOD = f"""name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@{SHA} # v3
      - run: ruff check .
      - run: pytest -q
      - run: docker build -t app .
"""


def test_rule_metadata():
    rules = [r for r in REGISTRY if r.id.startswith("CIC")]
    assert [r.id for r in rules] == [f"CIC00{i}" for i in range(1, 10)]
    for r in rules:
        assert r.dimension is Dimension.cicd
        assert r.description.strip() and r.remediation.strip()
        assert r.run.__module__ == "rung.probes.cicd"


def test_good_workflow_passes_everything(make_repo):
    repo = make_repo({WF: GOOD})
    for r in (r for r in REGISTRY if r.id.startswith("CIC")):
        assert r.run(repo).outcome is Outcome.passed, r.id


def test_cic001(make_repo):
    bad = cicd.pipeline_defined(make_repo({"README.md": "ci"}))
    assert bad.outcome is Outcome.failed and bad.hits[0].path == ".github/workflows"
    assert (
        cicd.pipeline_defined(make_repo({".gitlab-ci.yml": "test:\n  script: [pytest]\n"})).outcome
        is Outcome.passed
    )
    # a YAML file elsewhere under .github is not a pipeline
    assert (
        cicd.pipeline_defined(make_repo({".github/dependabot.yml": "version: 2\n"})).outcome
        is Outcome.failed
    )


def test_cic002(make_repo):
    manual = "on:\n  workflow_dispatch:\n  schedule:\n    - cron: '0 0 * * *'\njobs: {}\n"
    bad = cicd.runs_automatically(make_repo({WF: manual}))
    assert bad.outcome is Outcome.failed and bad.hits[0].line == 1
    tag_only = "on:\n  push:\n    tags: ['v*']\njobs: {}\n"
    assert cicd.runs_automatically(make_repo({WF: tag_only})).outcome is Outcome.failed
    # bare `on: push` is parsed by PyYAML as {True: 'push'}
    assert (
        cicd.runs_automatically(make_repo({WF: "on: push\njobs: {}\n"})).outcome is Outcome.passed
    )
    assert (
        cicd.runs_automatically(make_repo({".travis.yml": "script: make\n"})).outcome
        is Outcome.passed
    )
    assert cicd.runs_automatically(make_repo({"a.txt": "x"})).outcome is Outcome.not_applicable
    assert (
        cicd.runs_automatically(make_repo({WF: "on: [push\n  : :"})).outcome
        is Outcome.not_applicable
    )


def test_cic003(make_repo):
    build_only = (
        "on: push\njobs:\n  test:\n    name: test\n    steps:\n"
        "      - run: make build\n      # - run: pytest\n      - run: echo latest\n"
    )
    bad = cicd.runs_tests(make_repo({WF: build_only}))
    assert bad.outcome is Outcome.failed and bad.hits[0].path == WF
    assert cicd.runs_tests(make_repo({"a.py": "pytest"})).outcome is Outcome.failed
    ok = cicd.runs_tests(make_repo({"Jenkinsfile": "stage('t') { sh './gradlew check' }\n"}))
    assert ok.outcome is Outcome.passed and ok.evidence[0].start_line == 1


def test_cic004(make_repo):
    assert (
        cicd.runs_lint(
            make_repo({WF: "on: push\njobs:\n  a:\n    steps:\n      - run: black .\n"})
        ).outcome
        is Outcome.failed
    )
    assert (
        cicd.runs_lint(
            make_repo({WF: "on: push\njobs:\n  a:\n    steps:\n      - run: npm run lint\n"})
        ).outcome
        is Outcome.passed
    )


def test_cic005(make_repo):
    assert (
        cicd.delivery_automated(
            make_repo({WF: "on: push\njobs:\n  a:\n    steps:\n      - run: pytest\n"})
        ).outcome
        is Outcome.failed
    )
    rel = (
        "on:\n  release:\n    types: [published]\njobs:\n  a:\n    steps:\n      - run: ./ship.sh\n"
    )
    assert cicd.delivery_automated(make_repo({WF: rel})).outcome is Outcome.passed
    assert (
        cicd.delivery_automated(
            make_repo({".gitlab-ci.yml": "deploy_prod:\n  stage: deploy\n  script: [./go.sh]\n"})
        ).outcome
        is Outcome.passed
    )


def test_cic006(make_repo):
    wf = (
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: some/action@v1\n"
        "      - uses: actions/setup-node@main\n"
        "      - uses: docker://alpine:3.20\n"
        f"      - uses: other/thing/sub@{SHA}\n"
        "      - uses: ./.github/actions/local\n"
        "      - uses: docker://alpine@sha256:" + "b" * 64 + "\n"
        "      # - uses: commented/out@v1\n"
    )
    res = cicd.actions_pinned(make_repo({WF: wf}))
    assert res.outcome is Outcome.failed
    assert [h.line for h in res.hits] == [6, 7, 8]
    assert res.hits[1].severity is not None and res.hits[0].severity is None
    assert cicd.actions_pinned(make_repo({"a": "uses: x/y@v1"})).outcome is Outcome.not_applicable


def test_cic007(make_repo):
    none = "on: push\njobs:\n  build:\n    steps: []\n  lint:\n    permissions: {}\n    steps: []\n"
    bad = cicd.token_permissions(make_repo({WF: none}))
    assert (
        bad.outcome is Outcome.failed and bad.hits[0].line == 3 and "build" in bad.hits[0].message
    )
    wa = cicd.token_permissions(make_repo({WF: "on: push\npermissions: write-all\njobs: {}\n"}))
    assert wa.outcome is Outcome.failed and wa.hits[0].line == 2
    per_job = "on: push\njobs:\n  build:\n    permissions:\n      contents: read\n    steps: []\n"
    assert cicd.token_permissions(make_repo({WF: per_job})).outcome is Outcome.passed
    assert (
        cicd.token_permissions(
            make_repo({WF: "on: push\npermissions: {}\njobs:\n  b:\n    steps: []\n"})
        ).outcome
        is Outcome.passed
    )


def test_cic008(make_repo):
    bad = """on: pull_request
jobs:
  a:
    steps:
      - name: greet
        run: echo "${{ github.event.pull_request.title }}"
      - run: |
          echo start
          git log -1 ${{ github.head_ref }}
"""
    res = cicd.no_script_injection(make_repo({WF: bad}))
    assert res.outcome is Outcome.failed and [h.line for h in res.hits] == [6, 9]
    safe = """on: pull_request
jobs:
  a:
    if: ${{ github.event.pull_request.title != 'wip' }}
    steps:
      - uses: some/act@v1
        with:
          title: ${{ github.event.pull_request.title }}
      - run: |
          echo "$TITLE" ${{ github.event.pull_request.number }} ${{ github.sha }}
          echo ${{ contains(github.event.comment.body, '/go') }}
        env:
          TITLE: ${{ github.event.pull_request.title }}
"""
    assert cicd.no_script_injection(make_repo({WF: safe})).outcome is Outcome.passed


def test_cic009(make_repo):
    bad = """on:
  pull_request_target:
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"""
    res = cicd.no_pwn_request(make_repo({WF: bad}))
    assert res.outcome is Outcome.failed and res.hits[0].line == 8
    # same trigger, but only the trusted base branch is checked out
    labeler = bad.replace(
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", ""
    )
    assert cicd.no_pwn_request(make_repo({WF: labeler})).outcome is Outcome.passed
    # checking out the head under plain pull_request is harmless
    assert (
        cicd.no_pwn_request(
            make_repo({WF: bad.replace("pull_request_target", "pull_request")})
        ).outcome
        is Outcome.passed
    )
