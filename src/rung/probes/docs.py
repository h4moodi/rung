"""Documentation probe (``Dimension.docs``, rules ``DOC001``..``DOC011``).

Rules look for the documents a project is expected to carry at each stage. Matching is by
file name (case-insensitive, any documentation extension) in the conventional locations;
only the README and package manifests are ever opened.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable, Sequence
from pathlib import PurePosixPath

from rung.collect import RepoSnapshot
from rung.models import Check, Confidence, Dimension, Severity, Stage
from rung.registry import rule

#: Extensions a prose document may carry ("" = no extension, e.g. ``LICENSE``).
DOC_EXTENSIONS = ("", ".md", ".markdown", ".mdx", ".rst", ".txt", ".adoc", ".asciidoc", ".org")
#: Where community-health files are looked up (the locations GitHub and GitLab honour).
COMMUNITY_DIRS = ("", "docs", ".github", ".gitlab")

MIN_README_WORDS = 150  # DOC003
MIN_DOCS_PAGES = 2  # DOC007: prose files under docs/ that make it "project docs"
MAX_EVIDENCE = 3  # evidence paths listed by a passing rule

_SETUP_HEADING_RE = re.compile(
    r"\b(?:install\w*|set[\s-]?up|usage|using|getting[\s-]started|quick[\s-]?start|how\s+to"
    r"|run(?:ning)?|build(?:ing)?|develop(?:ment|ing)?|requirements|prerequisites"
    r"|examples?|deploy\w*|configur\w+)\b",
    re.IGNORECASE,
)
_CONTRIBUTING_HEADING_RE = re.compile(r"\bcontribut\w+", re.IGNORECASE)
_ATX_HEADING_RE = re.compile(r"^\s{0,3}(?:#{1,6}|={1,6})\s+(\S.*)$")
_UNDERLINE_RE = re.compile(r"^\s*([=\-~^\"'`*+#])\1{2,}\s*$")
_HTML_HEADING_RE = re.compile(r"<h[1-6][^>]*>(.*?)</h[1-6]>", re.IGNORECASE)
_CODE_BLOCK_RE = re.compile(r"^\s*(?:```|~~~|\.\. (?:code-block|code|sourcecode)::|\[source)")
_NOISE_RE = re.compile(r"https?://\S+|<[^>]+>|!?\[([^\]]*)\]\([^)]*\)")
_WORD_RE = re.compile(r"[A-Za-z0-9][\w'-]*")
_NO_LICENSE_VALUES = frozenset({"", "unlicensed", "proprietary", "none"})


# ------------------------------------------------------------------------ helpers


def _is_doc_named(path: str, stems: Sequence[str]) -> bool:
    """True if the file is ``<stem><doc extension>`` for one of ``stems``."""
    name = PurePosixPath(path).name.lower()
    return any(name == f"{stem.lower()}{ext}" for stem in stems for ext in DOC_EXTENSIONS)


def _in_dirs(path: str, dirs: Iterable[str]) -> bool:
    parent = PurePosixPath(path).parent.as_posix().lower()
    return ("" if parent == "." else parent) in dirs


def find_docs(repo: RepoSnapshot, stems: Sequence[str], dirs: Sequence[str] = ("",)) -> list[str]:
    """Files named after one of ``stems`` located directly inside one of ``dirs``."""
    return [f for f in repo.files if _in_dirs(f, dirs) and _is_doc_named(f, stems)]


def _under(repo: RepoSnapshot, *prefixes: str) -> list[str]:
    """Files anywhere below one of the given directories (case-insensitive)."""
    lowered = tuple(p.lower().rstrip("/") + "/" for p in prefixes)
    return [f for f in repo.files if f.lower().startswith(lowered)]


def find_readme(repo: RepoSnapshot) -> str | None:
    """The README a forge would render: root first, then ``docs/`` and ``.github/``."""
    for directory in ("", "docs", ".github"):
        found = find_docs(repo, ("README",), (directory,))
        if found:
            return found[0]
    return None


def _headings(lines: Sequence[str]) -> list[str]:
    """Heading texts from Markdown, reStructuredText, AsciiDoc and inline HTML."""
    out: list[str] = []
    for i, line in enumerate(lines):
        if m := _ATX_HEADING_RE.match(line):
            out.append(m.group(1))
        elif i and _UNDERLINE_RE.match(line) and lines[i - 1].strip():
            out.append(lines[i - 1])
        out.extend(_HTML_HEADING_RE.findall(line))
    return out


def _word_count(text: str) -> int:
    """Prose words; URLs, HTML tags and link/badge targets do not count."""
    return len(_WORD_RE.findall(_NOISE_RE.sub(r" \1 ", text)))


def _present(found: Sequence[str], what: str) -> Check:
    return Check.ok(f"{what} found at {found[0]}", evidence=found[:MAX_EVIDENCE])


def _declared_license(repo: RepoSnapshot) -> tuple[str, str] | None:
    """``(manifest, licence)`` when a root package manifest declares a licence."""
    try:
        package = json.loads(repo.read_text("package.json") or "{}")
    except ValueError:
        package = {}
    declared: object = package.get("license") if isinstance(package, dict) else None
    if _is_license_value(declared):
        return "package.json", str(declared)
    for manifest, table in (("pyproject.toml", "project"), ("Cargo.toml", "package")):
        try:
            data = tomllib.loads(repo.read_text(manifest) or "")
        except tomllib.TOMLDecodeError:
            continue
        declared = data.get(table, {}).get("license") if isinstance(data.get(table), dict) else None
        if isinstance(declared, dict):
            declared = declared.get("text")
        if _is_license_value(declared):
            return manifest, str(declared)
    return None


def _is_license_value(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    return normalized not in _NO_LICENSE_VALUES and not normalized.startswith("see license")


# -------------------------------------------------------------------------- rules


@rule(
    id="DOC001",
    title="README present",
    dimension=Dimension.docs,
    stage=Stage.inception,
    severity=Severity.medium,
    confidence=Confidence.high,
    description=(
        "A README is the entry point for every new contributor and user; without one "
        "nobody outside the founding team can tell what the project is."
    ),
    remediation="Add a README.md describing what the project is and how to run it.",
    weight=2.0,
)
def readme_present(repo: RepoSnapshot) -> Check:
    readme = find_readme(repo)
    if readme:
        return Check.ok(f"README found at {readme}", evidence=[readme])
    return Check.fail("No README at the repository root", at="README.md")


@rule(
    id="DOC002",
    title=".gitignore present",
    dimension=Dimension.docs,
    stage=Stage.inception,
    severity=Severity.low,
    confidence=Confidence.high,
    description=(
        "Without a .gitignore, build output, dependencies, editor files and local "
        "secrets such as .env end up committed from the very first days."
    ),
    remediation=(
        "Add a .gitignore for your stack (see github.com/github/gitignore) covering "
        "build output, dependency directories and local environment files."
    ),
)
def gitignore_present(repo: RepoSnapshot) -> Check:
    found = [f for f in repo.find_named(".gitignore") if f.count("/") <= 1]
    if repo.exists(".gitignore"):
        return Check.ok(".gitignore found at the repository root", evidence=[".gitignore"])
    if found:
        return Check.ok(
            f"No root .gitignore, but {len(found)} top-level project director"
            f"{'y has' if len(found) == 1 else 'ies have'} their own",
            evidence=found[:MAX_EVIDENCE],
        )
    return Check.fail("No .gitignore at the repository root", at=".gitignore")


@rule(
    id="DOC003",
    title="README explains how to set up and use the project",
    dimension=Dimension.docs,
    stage=Stage.stabilization,
    severity=Severity.medium,
    confidence=Confidence.medium,
    description=(
        "Once the product is released, first customers and new team members must be able "
        "to install and run it from the README alone; a title and a tagline are not enough."
    ),
    remediation=(
        "Expand the README with what the project does plus an Installation / Usage "
        "section containing the exact commands to run."
    ),
)
def readme_substantive(repo: RepoSnapshot) -> Check:
    readme = find_readme(repo)
    if readme is None:
        return Check.na("No README to assess (see DOC001)")
    text = repo.read_text(readme)
    if text is None:
        return Check.na(f"{readme} could not be read as text")
    lines = text.splitlines()
    words = _word_count(text)
    setup_heading = any(_SETUP_HEADING_RE.search(h) for h in _headings(lines))
    code_block = any(_CODE_BLOCK_RE.match(line) for line in lines)
    measured = (
        f"{readme} has {words} word(s), "
        f"{'a' if setup_heading else 'no'} setup/usage heading and "
        f"{'a' if code_block else 'no'} code block"
    )
    if words >= MIN_README_WORDS and (setup_heading or code_block):
        return Check.ok(measured, evidence=[readme])
    return Check.fail(
        f"{measured}; expected at least {MIN_README_WORDS} words and a setup/usage "
        "heading or a code block",
        at=readme,
    )


@rule(
    id="DOC004",
    title="License present",
    dimension=Dimension.docs,
    stage=Stage.stabilization,
    severity=Severity.medium,
    confidence=Confidence.high,
    description=(
        "A released product needs explicit terms: without a license nobody may legally "
        "use, modify or redistribute the code, and customers cannot adopt it."
    ),
    remediation=(
        "Add a LICENSE file at the repository root (choosealicense.com helps pick one) "
        "and reference it from the package manifest."
    ),
)
def license_present(repo: RepoSnapshot) -> Check:
    found = [
        f
        for f in repo.files
        if "/" not in f
        and re.match(r"(?:licen[cs]e|copying|unlicense)(?:[-.][\w.-]+)?$", f, re.IGNORECASE)
    ]
    found += [f for f in _under(repo, "LICENSES") if f not in found]
    if found:
        return _present(found, "License")
    declared = _declared_license(repo)
    if declared:
        manifest, name = declared
        return Check.ok(
            f"No LICENSE file, but {manifest} declares the license '{name[:40]}'; add the "
            "full license text as LICENSE",
            evidence=[manifest],
        )
    return Check.fail("No LICENSE file at the repository root", at="LICENSE")


@rule(
    id="DOC005",
    title="Contributing guide",
    dimension=Dimension.docs,
    stage=Stage.growth,
    severity=Severity.low,
    confidence=Confidence.high,
    description=(
        "As the team grows, onboarding by word of mouth stops scaling: a contributing "
        "guide records how to set up, branch, test and submit changes."
    ),
    remediation=(
        "Add CONTRIBUTING.md (root, docs/ or .github/) covering local setup, the branch "
        "and review workflow, and how to run the tests."
    ),
)
def contributing_guide(repo: RepoSnapshot) -> Check:
    found = find_docs(repo, ("CONTRIBUTING",), COMMUNITY_DIRS)
    if found:
        return _present(found, "Contributing guide")
    readme = find_readme(repo)
    if readme:
        for heading in _headings(repo.read_lines(readme)):
            if _CONTRIBUTING_HEADING_RE.search(heading):
                return Check.ok(
                    f"No CONTRIBUTING file, but {readme} has a contributing section",
                    evidence=[readme],
                )
    return Check.fail("No CONTRIBUTING guide in the root, docs/ or .github/", at="CONTRIBUTING.md")


@rule(
    id="DOC006",
    title="Changelog",
    dimension=Dimension.docs,
    stage=Stage.growth,
    severity=Severity.low,
    confidence=Confidence.high,
    description=(
        "A growing customer base needs to know what changed between versions; a "
        "changelog is the contract between releases and the people upgrading."
    ),
    remediation=(
        "Keep a CHANGELOG.md (keepachangelog.com) and update it with every "
        "user-visible change or release."
    ),
)
def changelog_present(repo: RepoSnapshot) -> Check:
    stems = (
        "CHANGELOG", "CHANGES", "HISTORY", "RELEASES", "RELEASE_NOTES", "RELEASE-NOTES",
        "RELEASENOTES", "NEWS",
    )  # fmt: skip
    found = find_docs(repo, stems, ("", "docs", "doc"))
    found += _under(repo, ".changeset", "changelog.d", "changelog", "changes", "newsfragments")
    if found:
        return _present(found, "Changelog")
    return Check.fail("No CHANGELOG, HISTORY, RELEASES or NEWS file", at="CHANGELOG.md")


@rule(
    id="DOC007",
    title="Project documentation or roadmap",
    dimension=Dimension.docs,
    stage=Stage.growth,
    severity=Severity.low,
    confidence=Confidence.high,
    description=(
        "Beyond the README, a scaling team needs shared documentation - guides, "
        "references or a roadmap - so that knowledge does not live in people's heads."
    ),
    remediation=(
        "Add a docs/ directory (or a docs site such as MkDocs, Docusaurus or Sphinx) "
        "and/or a ROADMAP.md stating where the project is heading."
    ),
)
def project_docs(repo: RepoSnapshot) -> Check:
    roadmap = find_docs(repo, ("ROADMAP",), ("", "docs", "doc", ".github"))
    if roadmap:
        return _present(roadmap, "Roadmap")
    site = repo.find_named(
        "mkdocs.yml", "mkdocs.yaml", "docusaurus.config.js", "docusaurus.config.ts",
        "docusaurus.config.mjs", ".readthedocs.yaml", ".readthedocs.yml", "book.toml",
        "antora.yml",
    )  # fmt: skip
    site += [f for f in _under(repo, "docs", "doc") if PurePosixPath(f).name == "conf.py"]
    if site:
        return _present(site, "Documentation site configuration")
    pages = [
        f
        for f in _under(repo, "docs", "doc")
        if PurePosixPath(f).suffix.lower() in DOC_EXTENSIONS[1:]
    ]
    if len(pages) >= MIN_DOCS_PAGES:
        return Check.ok(
            f"{len(pages)} documentation page(s) under {pages[0].split('/')[0]}/",
            evidence=pages[:MAX_EVIDENCE],
        )
    return Check.fail(
        f"No roadmap or docs site, and {len(pages)} documentation page(s) under docs/ "
        f"(expected at least {MIN_DOCS_PAGES})",
        at="docs",
    )


@rule(
    id="DOC008",
    title="CODEOWNERS",
    dimension=Dimension.docs,
    stage=Stage.growth,
    severity=Severity.medium,
    confidence=Confidence.high,
    description=(
        "With several contributors, every part of the codebase needs a named owner so "
        "reviews are routed automatically and nothing is orphaned."
    ),
    remediation=(
        "Add .github/CODEOWNERS (or CODEOWNERS / docs/CODEOWNERS) mapping paths to the "
        "people or teams responsible for them."
    ),
)
def codeowners_present(repo: RepoSnapshot) -> Check:
    found = [f for f in repo.find_named("CODEOWNERS") if _in_dirs(f, COMMUNITY_DIRS)]
    if found:
        return _present(found, "CODEOWNERS")
    return Check.fail("No CODEOWNERS file in the root, docs/ or .github/", at=".github/CODEOWNERS")


@rule(
    id="DOC009",
    title="Issue or pull request templates",
    dimension=Dimension.docs,
    stage=Stage.growth,
    severity=Severity.low,
    confidence=Confidence.high,
    description=(
        "Templates make incoming bug reports and change requests complete and "
        "comparable, which matters once more people than the founders file them."
    ),
    remediation=(
        "Add .github/ISSUE_TEMPLATE/ and .github/PULL_REQUEST_TEMPLATE.md (or "
        ".gitlab/issue_templates/ and .gitlab/merge_request_templates/)."
    ),
    weight=0.5,
)
def templates_present(repo: RepoSnapshot) -> Check:
    found = repo.glob(
        "ISSUE_TEMPLATE*", "PULL_REQUEST_TEMPLATE*",
        "docs/ISSUE_TEMPLATE*", "docs/PULL_REQUEST_TEMPLATE*",
        ".github/ISSUE_TEMPLATE*", ".github/PULL_REQUEST_TEMPLATE*",
        ".github/ISSUE_TEMPLATE/**", ".github/PULL_REQUEST_TEMPLATE/**",
        ".gitlab/issue_templates/**", ".gitlab/merge_request_templates/**",
    )  # fmt: skip
    if found:
        return _present(found, "Issue/PR template")
    return Check.fail("No issue or pull request templates", at=".github/ISSUE_TEMPLATE")


@rule(
    id="DOC010",
    title="Architecture documentation",
    dimension=Dimension.docs,
    stage=Stage.maturity,
    severity=Severity.medium,
    confidence=Confidence.high,
    description=(
        "An established product outlives its original authors: architecture documents "
        "and decision records preserve why the system is shaped the way it is."
    ),
    remediation=(
        "Add ARCHITECTURE.md or docs/architecture.md describing components and data "
        "flow, and record significant decisions as ADRs under docs/adr/."
    ),
)
def architecture_docs(repo: RepoSnapshot) -> Check:
    found = find_docs(repo, ("ARCHITECTURE", "DESIGN"), ("", "docs", "doc"))
    found += repo.glob("docs/architecture*", "doc/architecture*")
    found += _under(
        repo, "docs/architecture", "docs/adr", "docs/adrs", "docs/decisions", "docs/design",
        "doc/arch", "doc/adr", "doc/architecture", "adr",
    )  # fmt: skip
    found = sorted(set(found))
    if found:
        return _present(found, "Architecture documentation")
    return Check.fail(
        "No architecture documentation or decision records (ADRs)", at="docs/architecture.md"
    )


@rule(
    id="DOC011",
    title="Code of conduct",
    dimension=Dimension.docs,
    stage=Stage.maturity,
    severity=Severity.low,
    confidence=Confidence.high,
    description=(
        "A mature project with an external community states the behaviour it expects "
        "and how to report problems."
    ),
    remediation=(
        "Add CODE_OF_CONDUCT.md (the Contributor Covenant is a common starting point) "
        "with a contact for reports."
    ),
    weight=0.5,
)
def code_of_conduct(repo: RepoSnapshot) -> Check:
    found = find_docs(repo, ("CODE_OF_CONDUCT", "CODE-OF-CONDUCT"), COMMUNITY_DIRS)
    if found:
        return _present(found, "Code of conduct")
    return Check.fail("No CODE_OF_CONDUCT in the root, docs/ or .github/", at="CODE_OF_CONDUCT.md")
