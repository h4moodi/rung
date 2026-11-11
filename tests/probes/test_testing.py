# ruff: noqa: E501 - inline fixture trees read better on one line
from __future__ import annotations

from rung.models import Confidence, Dimension, Outcome
from rung.probes import testing
from rung.registry import REGISTRY

P, F, NA = Outcome.passed, Outcome.failed, Outcome.not_applicable
SRC = {f"src/app/m{i}.py": "x = 1\n" for i in range(10)}
PLACEHOLDER = '{"scripts": {"test": "echo \\"Error: no test specified\\" && exit 1"}}'


def test_rule_metadata():
    rules = [r for r in REGISTRY if r.id.startswith("TST")]
    assert [r.id for r in rules] == [f"TST00{i}" for i in range(1, 9)]
    for r in rules:
        assert r.dimension is Dimension.tests
        assert r.description.strip() and r.remediation.strip()


def test_test_file_recognition_across_languages():
    yes = ["tests/test_a.py", "pkg/a_test.go", "web/src/a.test.tsx", "web/__tests__/a.js",
           "src/test/java/com/x/Foo.java", "spec/models/user_spec.rb", "crate/tests/it.rs",
           "App.Tests/FooTests.cs", "tests/Unit/FooTest.php", "e2e/login.spec.ts"]  # fmt: skip
    no = ["src/latest.py", "src/contest.go", "tests/conftest.py", "tests/__init__.py",
          "node_modules/x/a.test.js", "tests/fixtures/repo/test_a.py", "src/main/java/KeySpec.java",
          "docs/test_plan.md", "src/protest.ts"]  # fmt: skip
    assert [p for p in yes if not testing.is_test_file(p)] == []
    assert [p for p in no if testing.is_test_file(p)] == []


def test_tst001(make_repo):
    bad = testing.tests_exist(make_repo({"src/app.py": "x", "src/latest.py": "x"}))
    assert bad.outcome is F and bad.hits[0].path == "tests/"
    assert testing.tests_exist(make_repo({"a.go": "x", "a_test.go": "x"})).outcome is P
    assert testing.tests_exist(make_repo({"README.md": "tests"})).outcome is NA


def test_tst002(make_repo):
    # the npm init placeholder is not a configured runner
    bad = testing.runner_configured(make_repo({"package.json": PLACEHOLDER, "src/a.js": "x"}))
    assert bad.outcome is F and bad.hits[0].path == "package.json"
    real = '{"scripts": {"test": "vitest run"}}'
    assert (
        testing.runner_configured(make_repo({"package.json": real, "src/a.js": "x"})).outcome is P
    )
    py = {"pyproject.toml": "[tool.pytest.ini_options]\n", "a.py": "x"}
    assert testing.runner_configured(make_repo(py)).outcome is P
    assert (
        testing.runner_configured(make_repo({"go.mod": "module x", "a_test.go": "x"})).outcome is P
    )
    assert (
        testing.runner_configured(
            make_repo({"Makefile": "test:\n\tgo test ./...\n", "a.c": "x"})
        ).outcome
        is P
    )
    assert testing.runner_configured(make_repo({"README.md": "x"})).outcome is NA


def test_tst003(make_repo):
    bad = testing.test_ratio(make_repo({**SRC, "tests/test_a.py": "x"}))
    assert bad.outcome is F and "ratio 0.10" in bad.summary
    assert (
        testing.test_ratio(
            make_repo({**SRC, "tests/test_a.py": "x", "tests/test_b.py": "x"})
        ).outcome
        is P
    )
    # too small to judge, and vendored/generated code is not counted as source
    small = {"a.py": "x", **{f"node_modules/p/f{i}.js": "x" for i in range(20)}}
    assert testing.test_ratio(make_repo(small)).outcome is NA


def test_tst004(make_repo):
    assert (
        testing.coverage_configured(make_repo({"a.py": "x", "README.md": "coverage: none"})).outcome
        is F
    )
    assert (
        testing.coverage_configured(
            make_repo({"a.py": "x", "pyproject.toml": "[tool.coverage.run]\n"})
        ).outcome
        is P
    )
    ci = {
        "a.go": "x",
        ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: go test -coverprofile=c.out ./...\n",
    }
    assert testing.coverage_configured(make_repo(ci)).outcome is P
    assert testing.coverage_configured(make_repo({"README.md": "x"})).outcome is NA


def test_tst005(make_repo):
    assert (
        testing.linter_configured(
            make_repo({"a.py": "x", "pyproject.toml": "[project]\nname='truffle'\n"})
        ).outcome
        is F
    )
    weak = testing.linter_configured(make_repo({"a.py": "x", ".editorconfig": "root = true\n"}))
    assert weak.outcome is F and weak.hits[0].confidence is Confidence.low
    assert (
        testing.linter_configured(
            make_repo({"a.py": "x", "pyproject.toml": "[tool.ruff]\n"})
        ).outcome
        is P
    )
    assert (
        testing.linter_configured(make_repo({"a.ts": "x", "web/eslint.config.mjs": "x"})).outcome
        is P
    )


def _history(make_repo, test_commits: int, total: int = 40):
    commits = [
        {
            "message": f"feat: c{i}",
            "files": {("tests/test_a.py" if i < test_commits else "a.py"): f"v{i}\n"},
        }
        for i in range(total)
    ]
    return make_repo({"a.py": "x", "tests/test_a.py": "x"}, commits=commits)


def test_tst006(make_repo):
    bad = testing.tests_maintained(_history(make_repo, test_commits=0))
    assert bad.outcome is F and "minimum 10%" in bad.summary
    assert testing.tests_maintained(_history(make_repo, test_commits=8)).outcome is P
    # young history and non-git trees cannot be judged
    assert testing.tests_maintained(_history(make_repo, test_commits=0, total=5)).outcome is NA
    assert testing.tests_maintained(make_repo({"tests/test_a.py": "x"}, git=False)).outcome is NA


def test_tst007(make_repo):
    bad = testing.multiple_test_levels(make_repo({"tests/test_a.py": "x", "tests/test_b.py": "x"}))
    assert bad.outcome is F and "unit" in bad.summary
    two = {"tests/unit/test_a.py": "x", "tests/integration/test_db.py": "x"}
    assert testing.multiple_test_levels(make_repo(two)).outcome is P
    assert (
        testing.multiple_test_levels(
            make_repo({"src/a.test.ts": "x", "playwright.config.ts": "x"})
        ).outcome
        is P
    )
    assert testing.multiple_test_levels(make_repo({"a.py": "x"})).outcome is NA


def test_tst008(make_repo):
    bad = testing.type_checking_configured(
        make_repo({"a.py": "x", "web/a.ts": "x", "web/tsconfig.json": '{"compilerOptions": {}}'})
    )
    assert bad.outcome is F and [h.path for h in bad.hits] == [
        "pyproject.toml",
        "web/tsconfig.json",
    ]
    ok = {
        "a.py": "x",
        "pyproject.toml": "[tool.mypy]\n",
        "web/a.ts": "x",
        "web/tsconfig.json": '{"compilerOptions": {"strict": true}}',
    }
    assert testing.type_checking_configured(make_repo(ok)).outcome is P
    # statically typed languages are not judged
    assert (
        testing.type_checking_configured(make_repo({"main.go": "x", "go.mod": "x"})).outcome is NA
    )
