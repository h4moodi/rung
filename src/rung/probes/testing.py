# ruff: noqa: E501 - pattern tables and rule texts are kept one entry per line
"""Testing probe: are there automated tests and the tooling around them? (rules TST001-TST008)

Language-agnostic and static: tests are recognised by path and name conventions, tooling
by its configuration files. Nothing is executed.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from rung.collect import RepoSnapshot
from rung.models import Check, Confidence, Dimension, Hit, Severity, Stage
from rung.probes._build_common import ci_files, is_vendored
from rung.registry import rule

#: Minimum test-file to source-file ratio expected of a growing product.
MIN_TEST_RATIO = 0.15
#: Below this many source files the ratio is too noisy to judge.
MIN_SOURCE_FILES_FOR_RATIO = 10
#: Commit window and thresholds for "tests are maintained alongside code".
RECENT_COMMITS = 100
MIN_COMMITS_FOR_HISTORY = 30
MIN_TEST_COMMIT_SHARE = 0.10
#: A language is judged for type checking when it makes up this share of source files.
MIN_LANGUAGE_SHARE = 0.20
#: Caps on configuration files read per rule.
MAX_CONFIG_FILES = 40
EXPECTED_TEST_PATH = "tests/"

SOURCE_EXTENSIONS = frozenset(
    {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".rb", ".rs",
     ".php", ".cs", ".c", ".cc", ".cpp", ".swift", ".scala", ".ex", ".exs", ".dart", ".vue",
     ".svelte"}
)  # fmt: skip
_PY = frozenset({".py"})
_JS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"})
_TEST_DIRS = frozenset({"tests", "test", "__tests__", "spec", "specs", "e2e", "testing"})
_NON_PRODUCT_DIRS = frozenset({"docs", "doc", "examples", "example", "samples", "migrations"})
_GENERATED = re.compile(r"\.min\.(?:js|css)$|\.d\.ts$|_pb2(?:_grpc)?\.py$|\.pb\.go$|\.generated\.")
_SCAFFOLD = re.compile(r"^(?:setup\.py|conftest\.py|__init__\.py|.*\.config\.[cm]?[jt]s)$")
_TEST_NAME = re.compile(
    r"""(?x)^(?:
      test_.*\.(?:py|rb|c|cc|cpp)
    | .*_test\.(?:py|go|rb|exs|dart|c|cc|cpp)
    | .*_spec\.rb
    | .*\.(?:test|spec|cy|e2e|e2e-spec)\.[cm]?[jt]sx?
    | .*(?:Test|Tests|TestCase|IT)\.(?:java|kt|scala|groovy|cs|php|swift)
    | .*Spec\.(?:kt|scala|groovy)
    )$"""
)
_JVM = (".java", ".kt", ".scala", ".groovy")

#: Test levels beyond plain unit tests, recognised from directory or file names.
_LEVELS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("integration", re.compile(r"(?:^|/)(?:integration|integration[_-]?tests?|it)/|integration|IT\.java$", re.I)),
    ("end-to-end", re.compile(r"(?:^|/)(?:e2e|end[-_]?to[-_]?end|cypress|playwright|selenium|system|smoke)/|\.(?:e2e|cy|e2e-spec)\.", re.I)),
    ("acceptance", re.compile(r"(?:^|/)(?:acceptance|functional|bdd|features)/", re.I)),
    ("contract", re.compile(r"(?:^|/)(?:contract|contracts|pact|pacts)/", re.I)),
    ("performance", re.compile(r"(?:^|/)(?:load|perf|performance|benchmarks?|bench|stress|k6)/", re.I)),
)  # fmt: skip
_LEVEL_CONFIGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("end-to-end", ("**/playwright.config.*", "**/cypress.config.*", "**/cypress.json", "**/wdio.conf.*")),
    ("performance", ("**/locustfile.py", "**/*.jmx", "**/*.k6.js")),
    ("acceptance", ("**/*.feature",)),
)  # fmt: skip

# name globs that prove a tool is configured just by existing
_RUNNER_FILES = (
    "**/pytest.ini", "**/tox.ini", "**/noxfile.py", "**/jest.config.*", "**/vitest.config.*",
    "**/.mocharc*", "**/playwright.config.*", "**/cypress.config.*", "**/karma.conf.*",
    "**/phpunit.xml*", "**/.rspec", "**/Cargo.toml", "**/mix.exs",
)  # fmt: skip
_COVERAGE_FILES = (
    ".coveragerc", "codecov.yml", ".codecov.yml", "codecov.yaml", ".coveralls.yml", ".nycrc*",
    ".c8rc*", ".simplecov", ".octocov.yml",
)  # fmt: skip
_LINT_FILES = (
    "**/ruff.toml", "**/.ruff.toml", "**/.flake8", "**/.pylintrc", "**/pylintrc", "**/.eslintrc*",
    "**/eslint.config.*", "**/.prettierrc*", "**/prettier.config.*", "**/biome.json*",
    "**/.golangci.*", "**/.rubocop.yml", "**/checkstyle*.xml", "**/rustfmt.toml",
    "**/.rustfmt.toml", "**/clippy.toml", "**/.clippy.toml", ".pre-commit-config.yaml",
    "**/.stylelintrc*", "**/phpcs.xml*", "**/.php-cs-fixer*", "**/phpstan.neon*",
    "**/.swiftlint.yml", "**/.clang-format", "**/.clang-tidy", "**/detekt.yml", "**/.scalafmt.conf",
    "**/.credo.exs", "**/.formatter.exs", "**/analysis_options.yaml", "**/tslint.json",
)  # fmt: skip
_TYPE_FILES_PY = ("**/mypy.ini", "**/.mypy.ini", "**/pyrightconfig.json", "**/.pyre_configuration")

# (file globs, content pattern): a tool declared inside a shared manifest
_MANIFESTS = (
    "**/pyproject.toml", "**/setup.cfg", "**/tox.ini", "**/requirements*.txt", "**/Pipfile",
    "**/package.json", "**/pom.xml", "**/build.gradle*", "**/Gemfile", "**/*.gemspec",
    "**/composer.json", "**/*.csproj", "**/Makefile", "**/justfile", "**/Taskfile.y*ml",
    "**/CMakeLists.txt", "**/pubspec.yaml", "**/Package.swift", "**/Rakefile", "**/jest.config.*",
    "**/vitest.config.*", "**/phpunit.xml*", ".pre-commit-config.yaml",
)  # fmt: skip
_NPM_PLACEHOLDER = re.compile(r'"test"\s*:\s*"(?:[^"\\]|\\.)*no test specified(?:[^"\\]|\\.)*"')
_RUNNER_CONTENT = re.compile(
    r"""(?x)
    \bpytest\b | \bnose2?\b | \[tool:pytest\]
    | "test"\s*:\s*"[^"]+" | "(?:jest|vitest|mocha|ava|jasmine|karma|cypress|@playwright/test|tap)"\s*:
    | \bjunit\b | \btestng\b | \bsurefire\b | \bspock\b | \bkotest\b | testImplementation | useJUnitPlatform
    | \brspec\b | \bminitest\b | \btest-unit\b
    | \bphpunit\b | \bpestphp\b | \bcodeception\b
    | Microsoft\.NET\.Test\.Sdk | \bxunit\b | \bnunit\b | \bMSTest\b
    | (?m:^(?:test|tests|check)[\w-]*\s*:) | enable_testing\(\) | \badd_test\( | flutter_test | testTarget\(
    """,
    re.I,
)
_COVERAGE_CONTENT = re.compile(
    r"""(?x)
    \[tool\.coverage | \[coverage: | \bpytest-cov\b | --cov\b | \bcoverage\s+(?:run|report|xml)\b
    | ^coverage\b | collectCoverage | coverageThreshold | --coverage\b | "(?:nyc|c8)" | @vitest/coverage
    | \bcoverage\s*: | \bjacoco\b | \bkover\b | \bcobertura\b | \bsimplecov\b | \btarpaulin\b
    | \bllvm-cov\b | <coverage\b | \bcoverlet\b | -cover(?:profile)?\b | \bcodecov\b | \bcoveralls\b
    """,
    re.I | re.M,
)
_LINT_CONTENT = re.compile(
    r"""(?x)
    \[tool\.(?:ruff|black|pylint|flake8|isort|yapf) | ^\[(?:flake8|pycodestyle|isort|pylint)
    | "(?:eslintConfig|prettier|eslint|@biomejs/biome|standard|xo|oxlint|lint)"\s*:
    | \bcheckstyle\b | \bspotless\b | \bktlint\b | \bdetekt\b | \bspotbugs\b | \bpmd\b
    | \brubocop\b | php_codesniffer | php-cs-fixer | \bphpstan\b | \bpsalm\b | laravel/pint
    | StyleCop | EnforceCodeStyleInBuild
    """,
    re.I | re.M,
)
_TYPE_CONTENT_PY = re.compile(
    r"\[tool\.(?:mypy|pyright|pyre|pytype|ty)\b|^\[mypy|\b(?:mypy|pyright)\b", re.M
)
_TS_STRICT = re.compile(r'"(?:strict|checkJs)"\s*:\s*true')
_TS_EXTENDS = re.compile(r'"extends"\s*:')


# ----------------------------------------------------------------------- helpers


def is_test_file(path: str) -> bool:
    """True when ``path`` follows a test naming/location convention of a supported language."""
    p = PurePosixPath(path)
    if is_vendored(path) or p.suffix.lower() not in SOURCE_EXTENSIONS | {".groovy"}:
        return False
    if _TEST_NAME.match(p.name):
        return True
    parts = p.parts[:-1]
    suffix = p.suffix.lower()
    if "__tests__" in parts and suffix in _JS:
        return True
    if suffix in _JVM and any(
        a == "src" and b in {"test", "androidTest"} for a, b in zip(parts, parts[1:], strict=False)
    ):
        return True
    if suffix == ".rs" and "tests" in parts:
        return True
    return suffix == ".cs" and any(d.endswith(("Tests", ".Test")) for d in parts)


def _is_source_file(path: str) -> bool:
    p = PurePosixPath(path)
    dirs = {d.lower() for d in p.parts[:-1]}
    return (
        p.suffix.lower() in SOURCE_EXTENSIONS
        and not is_vendored(path)
        and not dirs & (_TEST_DIRS | _NON_PRODUCT_DIRS)
        and not _GENERATED.search(p.name)
        and not _SCAFFOLD.match(p.name)
        and not is_test_file(path)
    )


def _inventory(repo: RepoSnapshot) -> tuple[list[str], list[str]]:
    """(test files, source files), both sorted."""
    return [f for f in repo.files if is_test_file(f)], [f for f in repo.files if _is_source_file(f)]


def _existing(repo: RepoSnapshot, globs: tuple[str, ...]) -> list[str]:
    return [f for f in repo.glob(*globs) if not is_vendored(f)]


def _declared(
    repo: RepoSnapshot, pattern: re.Pattern[str], extra: tuple[str, ...] = ()
) -> str | None:
    """First manifest/CI file (capped) whose content matches ``pattern``."""
    paths = _existing(repo, _MANIFESTS) + list(extra)
    for path in paths[:MAX_CONFIG_FILES]:
        text = repo.read_text(path) or ""
        if path.endswith("package.json"):
            text = _NPM_PLACEHOLDER.sub("", text)
        if pattern.search(text):
            return path
    return None


def _levels(repo: RepoSnapshot, tests: list[str]) -> dict[str, str]:
    """Detected test level -> one path that proves it."""
    found: dict[str, str] = {}
    for path in tests:
        level = next((name for name, rx in _LEVELS if rx.search(path)), "unit")
        found.setdefault(level, path)
    for level, globs in _LEVEL_CONFIGS:
        match = _existing(repo, globs)
        if match:
            found.setdefault(level, match[0])
    return found


# ------------------------------------------------------------------------- rules


@rule(
    id="TST001",
    title="Automated tests exist",
    dimension=Dimension.tests,
    stage=Stage.stabilization,
    severity=Severity.medium,
    description=(
        "After the first release every change risks breaking paying users; automated tests "
        "are the cheapest way to keep a released product dependable."
    ),
    remediation="Add a test suite (e.g. a tests/ directory) covering the core behaviour.",
    weight=2.0,
)
def tests_exist(repo: RepoSnapshot) -> Check:
    tests, sources = _inventory(repo)
    if tests:
        return Check.ok(f"{len(tests)} test file(s) found, e.g. {tests[0]}", evidence=tests[:3])
    if not sources:
        return Check.na("No source code detected")
    return Check.fail(
        f"No test files found for {len(sources)} source file(s)", at=EXPECTED_TEST_PATH
    )


@rule(
    id="TST002",
    title="Test runner configured",
    dimension=Dimension.tests,
    stage=Stage.stabilization,
    severity=Severity.low,
    description=(
        "Tests only stabilise a product if anyone (and CI) can run them with one documented "
        "command; a declared runner makes that command explicit."
    ),
    remediation=(
        "Declare the runner in the project manifest (pytest in pyproject.toml, a real "
        "`scripts.test` in package.json, a `test` Makefile target, ...)."
    ),
)
def runner_configured(repo: RepoSnapshot) -> Check:
    tests, sources = _inventory(repo)
    if not tests and not sources:
        return Check.na("No source code or tests detected")
    files = _existing(repo, _RUNNER_FILES)
    if files:
        return Check.ok(f"Test runner configuration found: {files[0]}", evidence=files[:1])
    if repo.find_named("go.mod") and any(t.endswith("_test.go") for t in tests):
        return Check.ok(
            "Go's built-in `go test` runner applies (go.mod + *_test.go)", evidence=["go.mod"]
        )
    declared = _declared(repo, _RUNNER_CONTENT)
    if declared:
        return Check.ok(f"A test runner is declared in {declared}", evidence=[declared])
    expected = "package.json" if repo.exists("package.json") else "pyproject.toml"
    return Check.fail(
        f"No test runner configuration or declaration found ({len(tests)} test file(s))",
        at=expected,
    )


@rule(
    id="TST003",
    title="Test suite is proportionate to the code",
    dimension=Dimension.tests,
    stage=Stage.growth,
    severity=Severity.medium,
    confidence=Confidence.medium,
    description=(
        "As the team and codebase grow, a token test suite stops protecting anything; the "
        "amount of test code should keep pace with the amount of product code."
    ),
    remediation=f"Add tests until there is roughly one test file per {round(1 / MIN_TEST_RATIO)} source files.",
)
def test_ratio(repo: RepoSnapshot) -> Check:
    tests, sources = _inventory(repo)
    if len(sources) < MIN_SOURCE_FILES_FOR_RATIO:
        return Check.na(
            f"Only {len(sources)} source file(s); ratio judged from {MIN_SOURCE_FILES_FOR_RATIO}"
        )
    ratio = len(tests) / len(sources)
    facts = f"{len(tests)} test file(s) for {len(sources)} source file(s) (ratio {ratio:.2f}, minimum {MIN_TEST_RATIO})"
    if ratio >= MIN_TEST_RATIO:
        return Check.ok(facts, evidence=tests[:3])
    return Check.fail(facts, at=EXPECTED_TEST_PATH)


@rule(
    id="TST004",
    title="Coverage measurement configured",
    dimension=Dimension.tests,
    stage=Stage.growth,
    severity=Severity.low,
    confidence=Confidence.medium,
    description=(
        "With several contributors nobody knows which code is untested unless it is measured; "
        "coverage reporting keeps test gaps visible as the product grows."
    ),
    remediation="Configure coverage (pytest-cov, jest --coverage, jacoco, `go test -cover`, ...) and report it in CI.",
)
def coverage_configured(repo: RepoSnapshot) -> Check:
    tests, sources = _inventory(repo)
    if not tests and not sources:
        return Check.na("No source code or tests detected")
    files = _existing(repo, _COVERAGE_FILES)
    if files:
        return Check.ok(f"Coverage configuration found: {files[0]}", evidence=files[:1])
    declared = _declared(repo, _COVERAGE_CONTENT, extra=ci_files(repo).files)
    if declared:
        return Check.ok(f"Coverage measurement is configured in {declared}", evidence=[declared])
    return Check.fail(
        f"No coverage configuration found (checked up to {MAX_CONFIG_FILES} manifest and CI files)",
        at=".coveragerc" if any(s.endswith(".py") for s in sources) else "codecov.yml",
    )


@rule(
    id="TST005",
    title="Linter or formatter configured",
    dimension=Dimension.tests,
    stage=Stage.stabilization,
    severity=Severity.low,
    description=(
        "A linter catches whole classes of defects before they are released and keeps the "
        "code readable for whoever joins next."
    ),
    remediation="Add and configure a linter/formatter for the main language (ruff, eslint + prettier, golangci-lint, ...).",
)
def linter_configured(repo: RepoSnapshot) -> Check:
    tests, sources = _inventory(repo)
    if not tests and not sources:
        return Check.na("No source code detected")
    files = _existing(repo, _LINT_FILES)
    if files:
        return Check.ok(f"Linter/formatter configuration found: {files[0]}", evidence=files[:1])
    declared = _declared(repo, _LINT_CONTENT)
    if declared:
        return Check.ok(f"A linter/formatter is configured in {declared}", evidence=[declared])
    if repo.exists(".editorconfig"):
        return Check.fail(
            "Only .editorconfig found: it sets editor defaults but enforces nothing",
            hits=[
                Hit(
                    ".editorconfig",
                    "Only .editorconfig found; no linter or formatter is configured",
                    confidence=Confidence.low,
                )
            ],
        )
    return Check.fail(
        "No linter or formatter configuration found",
        at="pyproject.toml" if any(s.endswith(".py") for s in sources) else ".editorconfig",
    )


@rule(
    id="TST006",
    title="Tests are maintained alongside code",
    dimension=Dimension.tests,
    stage=Stage.growth,
    severity=Severity.low,
    confidence=Confidence.medium,
    description=(
        "A test suite written once and then abandoned drifts away from the product; in a "
        "scaling team, tests must change in the same commits as the code they protect."
    ),
    remediation="Make tests part of the definition of done: change or add tests in the same commit/PR as the code.",
)
def tests_maintained(repo: RepoSnapshot) -> Check:
    if not repo.is_git or repo.is_shallow:
        return Check.na("No complete git history (not a git repo, or a shallow clone)")
    tests, _ = _inventory(repo)
    if not tests:
        return Check.na("No tests to maintain (reported by TST001)")
    recent = [c for c in repo.commits if not c.is_merge][:RECENT_COMMITS]
    if len(recent) < MIN_COMMITS_FOR_HISTORY:
        return Check.na(
            f"Only {len(recent)} non-merge commit(s); judged from {MIN_COMMITS_FOR_HISTORY}"
        )
    touching = sum(1 for c in recent if any(is_test_file(f) for f in c.files))
    share = touching / len(recent)
    facts = f"{touching} of the last {len(recent)} non-merge commits touch a test file ({share:.0%}, minimum {MIN_TEST_COMMIT_SHARE:.0%})"
    if share >= MIN_TEST_COMMIT_SHARE:
        return Check.ok(facts, evidence=tests[:1])
    return Check.fail(facts, at=EXPECTED_TEST_PATH)


@rule(
    id="TST007",
    title="More than one test level",
    dimension=Dimension.tests,
    stage=Stage.maturity,
    severity=Severity.low,
    confidence=Confidence.medium,
    description=(
        "Unit tests alone do not show that an established product works end to end; mature "
        "teams add integration, end-to-end, contract or performance tests on top."
    ),
    remediation="Add a second test level, e.g. tests/integration or an e2e suite (Playwright, Cypress, k6).",
)
def multiple_test_levels(repo: RepoSnapshot) -> Check:
    tests, _ = _inventory(repo)
    if not tests:
        return Check.na("No tests (reported by TST001)")
    levels = _levels(repo, tests)
    names = ", ".join(sorted(levels))
    if len(levels) >= 2:
        return Check.ok(
            f"{len(levels)} test levels detected: {names}", evidence=sorted(levels.values())[:3]
        )
    return Check.fail(
        f"Only one test level detected ({names}) across {len(tests)} test file(s)",
        at="tests/integration",
    )


@rule(
    id="TST008",
    title="Static type checking configured",
    dimension=Dimension.tests,
    stage=Stage.maturity,
    severity=Severity.low,
    confidence=Confidence.medium,
    description=(
        "In dynamically typed languages a type checker finds interface mistakes that tests "
        "miss and makes large, long-lived codebases safe to refactor."
    ),
    remediation='Configure mypy or pyright for Python, and enable `"strict": true` in tsconfig.json for TypeScript.',
)
def type_checking_configured(repo: RepoSnapshot) -> Check:
    _, sources = _inventory(repo)
    total = len(sources)
    share = {
        "Python": sum(PurePosixPath(s).suffix.lower() in _PY for s in sources),
        "JavaScript/TypeScript": sum(PurePosixPath(s).suffix.lower() in _JS for s in sources),
    }
    judged = [lang for lang, n in share.items() if total and n / total >= MIN_LANGUAGE_SHARE]
    if not judged:
        return Check.na("Only judged for Python and JavaScript/TypeScript code bases")
    hits: list[Hit] = []
    proof: list[str] = []
    if "Python" in judged:
        found = _existing(repo, _TYPE_FILES_PY)[:1] or [_declared(repo, _TYPE_CONTENT_PY)]
        if found[0]:
            proof.append(found[0])
        else:
            hits.append(Hit("pyproject.toml", "No mypy/pyright configuration for the Python code"))
    if "JavaScript/TypeScript" in judged:
        configs = _existing(repo, ("**/tsconfig*.json", "**/jsconfig.json"))[:MAX_CONFIG_FILES]
        texts = {c: repo.read_text(c) or "" for c in configs}
        # a config that extends a preset may inherit strictness: not provable, so not flagged
        good = [c for c, t in texts.items() if _TS_STRICT.search(t) or _TS_EXTENDS.search(t)]
        if good or repo.find_named(".flowconfig"):
            proof.append(good[0] if good else ".flowconfig")
        elif configs:
            hits.append(Hit(configs[0], "tsconfig does not enable `strict` type checking"))
        else:
            hits.append(Hit("tsconfig.json", "No tsconfig.json with `strict` for the JS/TS code"))
    if hits:
        return Check.fail(
            f"Type checking missing for {len(hits)} of {len(judged)} judged language(s)", hits=hits
        )
    return Check.ok(
        f"Type checking configured for {', '.join(judged)}: {', '.join(proof)}", evidence=proof
    )
