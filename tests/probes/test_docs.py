"""Documentation probe: one true-positive and one false-positive test per rule."""

from __future__ import annotations

import pytest

from rung.models import Dimension, Outcome, Severity, Stage
from rung.probes import docs
from rung.registry import REGISTRY

BARE = {"main.py": "print('hi')\n"}
LONG_TEXT = " ".join(["word"] * 160)


def test_registered_rules_are_well_formed():
    rules = [r for r in REGISTRY if r.id.startswith("DOC")]
    assert [r.id for r in rules] == [f"DOC{n:03d}" for n in range(1, 12)]
    assert len({r.run for r in rules}) == len(rules)
    for r in rules:
        assert r.dimension is Dimension.docs
        assert r.title and r.description.strip() and r.remediation.strip()
        assert r.run.__module__ == docs.__name__
    by_id = {r.id: r for r in rules}
    assert by_id["DOC001"].stage is Stage.inception
    assert by_id["DOC010"].stage is Stage.maturity
    assert (by_id["DOC011"].stage, by_id["DOC011"].severity) == (Stage.maturity, Severity.low)


# (rule, expected path of the failing hit, files that satisfy it despite looking unusual)
CASES = [
    (docs.readme_present, "README.md", {"readme.rst": "Project\n=======\n"}),
    (docs.readme_present, "README.md", {".github/README.md": "# hi\n"}),
    (docs.gitignore_present, ".gitignore", {".gitignore": "*.pyc\n"}),
    (docs.gitignore_present, ".gitignore", {"api/.gitignore": "x\n", "web/.gitignore": "y\n"}),
    (docs.license_present, "LICENSE", {"LICENCE.txt": "MIT\n"}),
    (docs.license_present, "LICENSE", {"LICENSE-APACHE": "Apache\n"}),
    (docs.license_present, "LICENSE", {"package.json": '{"name": "x", "license": "MIT"}'}),
    (docs.license_present, "LICENSE", {"pyproject.toml": '[project]\nlicense = {text = "MIT"}\n'}),
    (docs.contributing_guide, "CONTRIBUTING.md", {".github/CONTRIBUTING.md": "# How\n"}),
    (docs.contributing_guide, "CONTRIBUTING.md", {"README.md": "# x\n\n## Contributing\nPRs\n"}),
    (docs.changelog_present, "CHANGELOG.md", {"HISTORY.rst": "1.0\n"}),
    (docs.changelog_present, "CHANGELOG.md", {".changeset/config.json": "{}"}),
    (docs.project_docs, "docs", {"ROADMAP.md": "# Roadmap\n"}),
    (docs.project_docs, "docs", {"mkdocs.yml": "site_name: x\n"}),
    (docs.project_docs, "docs", {"docs/guide.md": "# a\n", "docs/api/ref.rst": "b\n"}),
    (docs.codeowners_present, ".github/CODEOWNERS", {"docs/CODEOWNERS": "* @a\n"}),
    (docs.templates_present, ".github/ISSUE_TEMPLATE", {".github/ISSUE_TEMPLATE/bug.yml": "x"}),
    (docs.templates_present, ".github/ISSUE_TEMPLATE", {".github/pull_request_template.md": "x"}),
    (docs.templates_present, ".github/ISSUE_TEMPLATE", {".gitlab/issue_templates/Bug.md": "x"}),
    (docs.architecture_docs, "docs/architecture.md", {"ARCHITECTURE.md": "# Arch\n"}),
    (docs.architecture_docs, "docs/architecture.md", {"docs/adr/0001-use-sqlite.md": "# 1\n"}),
    (docs.code_of_conduct, "CODE_OF_CONDUCT.md", {".github/CODE_OF_CONDUCT.md": "# CoC\n"}),
]


@pytest.mark.parametrize(
    ("rule_fn", "expected_path"), sorted({(c[0], c[1]) for c in CASES}, key=str)
)
def test_rule_fails_on_a_bare_repo_at_the_expected_path(make_repo, rule_fn, expected_path):
    check = rule_fn(make_repo(BARE))
    assert check.outcome is Outcome.failed
    assert [h.path for h in check.hits] == [expected_path]


@pytest.mark.parametrize(("rule_fn", "expected_path", "files"), CASES)
def test_rule_passes_on_alternative_spellings_and_locations(
    make_repo, rule_fn, expected_path, files
):
    check = rule_fn(make_repo({**BARE, **files}))
    assert check.outcome is Outcome.passed
    assert check.evidence and check.evidence[0].path in files


@pytest.mark.parametrize(
    ("rule_fn", "files"),
    [
        (docs.readme_present, {"src/pkg/README.md": "# nested only\n"}),
        (docs.gitignore_present, {"vendor/lib/x/.gitignore": "*\n"}),
        (docs.license_present, {"package.json": '{"license": "UNLICENSED"}'}),
        (docs.license_present, {"src/license_checker.py": "x = 1\n"}),
        (docs.contributing_guide, {"README.md": "# x\n\nThanks to all contributors.\n"}),
        (docs.changelog_present, {"src/changelog.py": "x = 1\n"}),
        (docs.project_docs, {"docs/index.md": "# only one page\n", "docs/logo.png": b"\x89PNG"}),
        (docs.codeowners_present, {"src/CODEOWNERS": "* @a\n"}),
        (docs.templates_present, {"templates/issue.html": "<p>\n"}),
        (docs.architecture_docs, {"src/architecture.py": "x = 1\n"}),
        (docs.code_of_conduct, {"src/conduct.py": "x = 1\n"}),
    ],
)
def test_rule_still_fails_on_lookalikes(make_repo, rule_fn, files):
    assert rule_fn(make_repo({**BARE, **files})).outcome is Outcome.failed


def test_rules_work_on_a_plain_directory(make_repo):
    repo = make_repo({"README.md": "# x\n", ".gitignore": "*.pyc\n"}, git=False)
    assert docs.readme_present(repo).outcome is Outcome.passed
    assert docs.gitignore_present(repo).outcome is Outcome.passed


# ------------------------------------------------------------------------- DOC003


def test_doc003_fails_on_a_stub_readme(make_repo):
    check = docs.readme_substantive(make_repo({"README.md": "# widget\n\nA thing.\n"}))
    assert check.outcome is Outcome.failed
    assert check.hits[0].path == "README.md"
    assert "3 word(s)" in check.summary and "no setup/usage heading" in check.summary


def test_doc003_fails_on_long_prose_without_setup_help(make_repo):
    check = docs.readme_substantive(make_repo({"README.md": f"# widget\n\n{LONG_TEXT}\n"}))
    assert check.outcome is Outcome.failed


def test_doc003_does_not_count_badges_and_urls_as_words(make_repo):
    badges = "\n".join(
        f"[![b{i}](https://img.example/a/b/c/{i}.svg)](https://ci.example/x/y/{i})"
        for i in range(80)
    )
    readme = f"# widget\n\n{badges}\n\n## Install\n\n```\npip install widget\n```\n"
    assert docs.readme_substantive(make_repo({"README.md": readme})).outcome is Outcome.failed


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("README.md", f"# widget\n\n{LONG_TEXT}\n\n## Getting started\n\nRun it.\n"),
        ("README.md", f"# widget\n\n{LONG_TEXT}\n\n```sh\nmake run\n```\n"),
        ("README.rst", f"widget\n======\n\n{LONG_TEXT}\n\nInstallation\n------------\n\npip.\n"),
        ("README.md", f"<h1>widget</h1>\n\n{LONG_TEXT}\n\n<h2>Usage</h2>\n\nRun it.\n"),
    ],
)
def test_doc003_passes_on_substantive_readmes_in_several_markups(make_repo, name, body):
    check = docs.readme_substantive(make_repo({name: body}))
    assert check.outcome is Outcome.passed
    assert check.evidence[0].path == name


def test_doc003_not_applicable_without_a_readme(make_repo):
    assert docs.readme_substantive(make_repo(BARE)).outcome is Outcome.not_applicable


def test_doc004_tolerates_a_broken_manifest(make_repo):
    repo = make_repo({"package.json": "{not json", "pyproject.toml": "[project\n"})
    assert docs.license_present(repo).outcome is Outcome.failed
