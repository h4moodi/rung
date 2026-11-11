"""CI/CD probe: is there a pipeline, what does it run, and is it safe? (rules CIC001-CIC009)

Static analysis only. Every provider is recognised for the "does CI exist / what does it
run" rules; the deeper supply-chain and injection rules understand GitHub Actions and
are not applicable when a repo has no GitHub workflows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from rung.collect import RepoSnapshot
from rung.models import Check, Confidence, Dimension, Hit, Location, Severity, Stage
from rung.probes._build_common import CiFiles, ci_files, code_lines, load_yaml
from rung.registry import rule

#: Upper bound on hits reported by one rule, so a huge monorepo cannot flood the report.
MAX_HITS = 50
#: Where a missing pipeline is reported.
EXPECTED_CI_PATH = ".github/workflows"

AUTOMATIC_TRIGGERS = frozenset({"push", "pull_request", "pull_request_target", "merge_group"})
#: Owners whose actions are maintained by GitHub itself; a version tag is accepted for them.
FIRST_PARTY_OWNERS = frozenset({"actions", "github"})

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_TAG_RE = re.compile(r"^v?\d+(\.\d+){0,2}$")
_USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?([^'\"\s#]+)")
_RUN_RE = re.compile(r"^(\s*)(-\s+)?run:(.*)$")
_EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}")

_TEST_COMMANDS = re.compile(
    r"""(?x)
    \b(?:pytest|py\.test|tox|nox|jest|vitest|mocha|rspec|phpunit|pest|ctest|karma)\b
    | \bpython\d?(?:\.\d+)?\s+-m\s+(?:unittest|pytest)\b
    | \b(?:npm|yarn|pnpm|bun)\s+(?:run\s+)?(?:test|ci|coverage|e2e)(?:[:\w-]*)\b
    | \b(?:go|cargo|dotnet|mix|swift|flutter|dart|deno|sbt|lein|bazel|nx|turbo|hatch)\s+
      (?:run\s+)?(?:test|nextest)\b
    | \b(?:mvn|mvnw)\b[^\n]*\b(?:test|verify|package|install)\b
    | \bgradlew?\b[^\n]*\b(?:test|check|build)\b
    | \b(?:make|just|task|invoke|rake|composer)\s+(?:test|tests|check|ci|spec)(?:[\w-]*)\b
    | \bplaywright\s+test\b | \bcypress\s+run\b
    """
)
_LINT_COMMANDS = re.compile(
    r"""(?x)
    \b(?:ruff|flake8|pylint|mypy|pyright|eslint|golangci-lint|staticcheck|rubocop|pre-commit
       |shellcheck|hadolint|checkstyle|spotbugs|spotless\w*|ktlint\w*|detekt|phpcs|phpstan|psalm
       |semgrep|bandit|actionlint|yamllint|markdownlint(?:-cli2?)?|stylelint|clang-tidy|cppcheck
       |swiftlint|tflint|oxlint)\b
    | \b(?:super-linter|megalinter|mega-linter|codeql-action|sonar\w*)\b
    | \bblack\b[^\n]*--(?:check|diff)\b | \bpsf/black\b
    | \bprettier\b[^\n]*--(?:check|list-different)\b
    | \bbiome\s+(?:check|lint|ci)\b
    | \btsc\b[^\n]*--noEmit\b
    | \bgo\s+vet\b | \bgofmt\b
    | \bcargo\s+(?:clippy|fmt)\b
    | \bdotnet\s+format\b
    | \bmix\s+(?:credo|format)\b
    | \b(?:npm|yarn|pnpm|bun)\s+(?:run\s+)?(?:lint|typecheck|type-check|format:check)(?:[:\w-]*)\b
    | \b(?:make|just|task|invoke|rake|composer)\s+(?:lint|typecheck|format-check)(?:[\w-]*)\b
    """
)
_DELIVERY_COMMANDS = re.compile(
    r"""(?x)
    \bdocker\s+(?:buildx\s+)?(?:build|push)\b | \bdocker[\s-]compose\s+(?:build|push)\b
    | \b(?:docker/build-push-action|softprops/action-gh-release|actions/create-release
        |ncipollo/release-action|pypa/gh-action-pypi-publish|goreleaser(?:/goreleaser-action)?
        |actions/deploy-pages|peaceiris/actions-gh-pages|JamesIves/github-pages-deploy-action
        |googleapis/release-please-action|google-github-actions/release-please-action
        |changesets/action|helm/chart-releaser-action|aws-actions/amazon-ecs-deploy-task-definition
        |azure/webapps-deploy|google-github-actions/deploy-cloudrun|superfly/flyctl-actions
        |amondnet/vercel-action|cloudflare/wrangler-action)\b
    | \b(?:npm|yarn|pnpm)\s+publish\b | \btwine\s+upload\b
    | \b(?:poetry|uv|flit|hatch|cargo)\s+publish\b
    | \bgem\s+push\b | \bmvn\b[^\n]*\bdeploy\b | \bgradlew?\b[^\n]*\bpublish\w*\b
    | \bdotnet\s+nuget\s+push\b | \bgh\s+release\s+(?:create|upload)\b
    | \bsemantic-release\b | \brelease-please\b
    | \bhelm\s+(?:upgrade|install|push)\b
    | \bkubectl\s+(?:apply|set\s+image|rollout)\b
    | \b(?:terraform|tofu)\s+apply\b | \bpulumi\s+up\b | \bcdk\s+deploy\b
    | \baws\s+(?:s3\s+sync|ecs\s+update-service|lambda\s+update-function-code)\b
    | \bgcloud\b[^\n]*\bdeploy\b | \baz\s+(?:webapp|functionapp|containerapp)\b
    | \b(?:vercel|netlify|firebase|flyctl|fly|serverless|sls|wrangler|kamal)\s+
      (?:deploy|publish|--prod)\b
    | \bansible-playbook\b | \bargocd\s+app\s+sync\b | \bskaffold\s+(?:run|deploy)\b
    """
)
#: Job, stage or step names that announce delivery (weaker than a concrete command).
_DELIVERY_NAMES = re.compile(
    r"""(?xi)
    ^\s*(?:-\s+)?(?:name|stage|environment)\s*:\s*[^\#\n]*\b(?:deploy\w*|publish\w*|release\w*)\b
    | ^\s*(?:deploy|release|publish)[\w-]*\s*:\s*$
    """
)
#: `${{ }}` contexts an outside contributor controls (GitHub Security Lab's list).
_UNTRUSTED_CONTEXT = re.compile(
    r"""(?x)
    github\.head_ref
    | github\.event\.(?:
        (?:issue|pull_request|discussion)\.(?:title|body)
      | pull_request\.head\.(?:ref|label)
      | pull_request\.head\.repo\.default_branch
      | (?:comment|review|review_comment)\.body
      | pages(?:\[[^\]]*\]|\.\*|\.\d+)\.page_name
      | head_commit\.message
      | head_commit\.(?:author|committer)\.(?:email|name)
      | commits(?:\[[^\]]*\]|\.\*|\.\d+)\.(?:message|(?:author|committer)\.(?:email|name))
      | workflow_run\.(?:head_branch|head_commit\.message|display_title)
    )
    """
)
#: Expressions that only yield true/false cannot carry attacker text into the script.
_BOOLEAN_EXPR = re.compile(r"^\s*!?\s*(?:contains|startsWith|endsWith)\s*\(.*\)\s*$|[=!]=")
_PR_HEAD_REF = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/"
    r"|github\.event\.pull_request\.merge_commit_sha"
)
_PR_HEAD_FETCH = re.compile(
    r"\bgh\s+pr\s+checkout\b|\bgit\s+(?:fetch|pull|checkout)\b[^\n]*\bpull/[^\n]*/(?:head|merge)\b"
)


# ----------------------------------------------------------------------- helpers


@dataclass(frozen=True)
class _Workflow:
    """One GitHub Actions workflow: raw lines plus the parsed document (None if malformed)."""

    path: str
    lines: tuple[str, ...]
    doc: dict[Any, Any] | None

    @property
    def triggers(self) -> dict[str, Any]:
        """Event name -> its configuration. PyYAML reads the bare key ``on`` as ``True``."""
        if self.doc is None:
            return {}
        raw = self.doc.get("on", self.doc.get(True))
        if isinstance(raw, str):
            return {raw: None}
        if isinstance(raw, list):
            return {str(t): None for t in raw}
        if isinstance(raw, dict):
            return {str(k): v for k, v in raw.items()}
        return {}

    @property
    def jobs(self) -> dict[str, dict[Any, Any]]:
        jobs = self.doc.get("jobs") if self.doc else None
        if not isinstance(jobs, dict):
            return {}
        return {str(k): v for k, v in jobs.items() if isinstance(v, dict)}

    def line_of(self, pattern: re.Pattern[str]) -> int | None:
        for no, line in enumerate(self.lines, start=1):
            if pattern.search(line):
                return no
        return None


def _workflows(repo: RepoSnapshot, ci: CiFiles) -> list[_Workflow]:
    out: list[_Workflow] = []
    for path in ci.workflows:
        text = repo.read_text(path)
        if text is None:
            continue
        doc = load_yaml(text)
        out.append(
            _Workflow(path, tuple(text.splitlines()), doc if isinstance(doc, dict) else None)
        )
    return out


def _unparsed_note(workflows: list[_Workflow]) -> str:
    bad = sum(1 for w in workflows if w.doc is None)
    return f"; {bad} workflow(s) could not be parsed and were skipped" if bad else ""


def _first_command(
    repo: RepoSnapshot, ci: CiFiles, pattern: re.Pattern[str]
) -> tuple[Location, str] | None:
    """First CI line matching ``pattern``: its location and the matched command text."""
    for path in ci.files:
        for no, line in code_lines(repo, path):
            m = pattern.search(line)
            if m:
                return Location(path=path, start_line=no), " ".join(m.group(0).split())
    return None


def _no_ci(what: str) -> Check:
    return Check.fail(
        f"No CI pipeline is defined, so {what}",
        at=EXPECTED_CI_PATH,
    )


def _capped(hits: list[Hit]) -> tuple[list[Hit], str]:
    if len(hits) <= MAX_HITS:
        return hits, ""
    return hits[:MAX_HITS], f" (showing the first {MAX_HITS})"


def _runs_on_push(config: Any) -> bool:
    """A ``push`` trigger limited to tags is a release hook, not continuous integration."""
    if not isinstance(config, dict):
        return True
    tag_only = ("tags" in config or "tags-ignore" in config) and not (
        {"branches", "branches-ignore", "paths", "paths-ignore"} & set(config)
    )
    return not tag_only


def _run_blocks(lines: tuple[str, ...]) -> list[tuple[int, str]]:
    """``(line_no, text)`` of every line that belongs to a ``run:`` script.

    A ``run:`` value is the rest of its line plus every following line indented deeper
    than the key, which covers block scalars (``|``, ``>``) and multi-line plain scalars
    without needing YAML line marks.
    """
    out: list[tuple[int, str]] = []
    i, n = 0, len(lines)
    while i < n:
        m = _RUN_RE.match(lines[i])
        if not m:
            i += 1
            continue
        key_indent = len(m.group(1)) + len(m.group(2) or "")
        out.append((i + 1, m.group(3)))
        i += 1
        while i < n:
            line = lines[i]
            if line.strip() and len(line) - len(line.lstrip()) <= key_indent:
                break
            out.append((i + 1, line))
            i += 1
    return out


# ------------------------------------------------------------------------- rules


@rule(
    id="CIC001",
    title="CI pipeline defined",
    dimension=Dimension.cicd,
    stage=Stage.stabilization,
    severity=Severity.medium,
    confidence=Confidence.high,
    description=(
        "Once a product is released, every change must be built and checked the same way; "
        "a CI pipeline is what makes the product dependable for its first customers."
    ),
    remediation=(
        "Add a pipeline, e.g. .github/workflows/ci.yml, that installs the project and runs "
        "its checks on every push and pull request."
    ),
    weight=2.0,
)
def pipeline_defined(repo: RepoSnapshot) -> Check:
    ci = ci_files(repo)
    if not ci.files:
        return Check.fail(
            "No CI configuration found for any supported provider", at=EXPECTED_CI_PATH
        )
    providers = ", ".join(ci.providers)
    return Check.ok(
        f"{len(ci.files)} CI configuration file(s) found ({providers}){ci.cap_note}",
        evidence=list(ci.files[:5]),
    )


@rule(
    id="CIC002",
    title="CI runs automatically on push or pull request",
    dimension=Dimension.cicd,
    stage=Stage.stabilization,
    severity=Severity.medium,
    confidence=Confidence.high,
    description=(
        "A pipeline that only runs when someone remembers to click a button (or on a timer) "
        "does not protect the released product from a breaking change."
    ),
    remediation=(
        "Trigger the main workflow with `on: [push, pull_request]` (optionally filtered to "
        "your default branch) instead of only workflow_dispatch or schedule."
    ),
)
def runs_automatically(repo: RepoSnapshot) -> Check:
    ci = ci_files(repo)
    if not ci.files:
        return Check.na("No CI pipeline to inspect (reported by CIC001)")
    others = [p for p in ci.providers if p != "GitHub Actions"]
    workflows = _workflows(repo, ci)
    if not workflows:
        return Check.ok(
            f"{', '.join(others)} pipelines run on every push by default "
            "(triggers are only analysed for GitHub Actions)",
            evidence=list(ci.files[:1]),
        )
    parsed = [w for w in workflows if w.doc is not None]
    if not parsed:
        return Check.na(f"None of the {len(workflows)} GitHub workflow(s) could be parsed")
    seen: set[str] = set()
    for wf in parsed:
        triggers = wf.triggers
        seen.update(triggers)
        auto = sorted(
            t
            for t in AUTOMATIC_TRIGGERS & set(triggers)
            if t != "push" or _runs_on_push(triggers[t])
        )
        if auto:
            return Check.ok(
                f"{wf.path} runs on {', '.join(auto)}{_unparsed_note(workflows)}",
                evidence=[wf.path],
            )
    if others:
        return Check.ok(
            f"GitHub workflows are manual/scheduled only, but {', '.join(others)} "
            "pipelines run on every push by default",
            evidence=list(ci.files[:1]),
        )
    listed = ", ".join(sorted(seen)) or "none"
    trigger_line = re.compile(r"^\s*['\"]?on['\"]?\s*:")
    hits = [
        Hit(
            path=wf.path,
            message=(
                f"Workflow is only triggered by: {', '.join(sorted(wf.triggers)) or 'nothing'}; "
                "no push or pull_request trigger"
            ),
            line=wf.line_of(trigger_line),
        )
        for wf in parsed
    ]
    hits, note = _capped(hits)
    return Check.fail(
        f"None of the {len(parsed)} GitHub workflow(s) runs on push or pull_request "
        f"(triggers seen: {listed}){note}",
        hits=hits,
    )


@rule(
    id="CIC003",
    title="CI runs the tests",
    dimension=Dimension.cicd,
    stage=Stage.stabilization,
    severity=Severity.medium,
    confidence=Confidence.medium,
    description=(
        "Tests only stabilise a product if they run on every change; a pipeline that merely "
        "builds lets regressions reach the first customers."
    ),
    remediation=(
        "Add a CI step that runs the test suite (e.g. `pytest`, `npm test`, `go test ./...`) "
        "and fails the build when a test fails."
    ),
    weight=1.5,
)
def runs_tests(repo: RepoSnapshot) -> Check:
    ci = ci_files(repo)
    if not ci.files:
        return _no_ci("tests are not run automatically")
    found = _first_command(repo, ci, _TEST_COMMANDS)
    if found:
        loc, command = found
        return Check.ok(
            f"CI runs tests: `{command}` at {loc.path}:{loc.start_line}{ci.cap_note}",
            evidence=[loc],
        )
    return Check.fail(
        f"No test command found in {len(ci.files)} CI file(s){ci.cap_note}",
        at=ci.files[0],
    )


@rule(
    id="CIC004",
    title="CI runs lint or static analysis",
    dimension=Dimension.cicd,
    stage=Stage.growth,
    severity=Severity.low,
    confidence=Confidence.medium,
    description=(
        "As the team grows, style and correctness rules have to be enforced by the pipeline "
        "rather than by reviewers' memory, or review time and defect rates scale with headcount."
    ),
    remediation=(
        "Add a lint/static-analysis step to CI (e.g. `ruff check`, `eslint .`, "
        "`golangci-lint run`, `cargo clippy`, or `pre-commit run --all-files`)."
    ),
)
def runs_lint(repo: RepoSnapshot) -> Check:
    ci = ci_files(repo)
    if not ci.files:
        return _no_ci("no linter or static analyser runs automatically")
    found = _first_command(repo, ci, _LINT_COMMANDS)
    if found:
        loc, command = found
        return Check.ok(
            f"CI runs static analysis: `{command}` at {loc.path}:{loc.start_line}{ci.cap_note}",
            evidence=[loc],
        )
    return Check.fail(
        f"No lint or static-analysis command found in {len(ci.files)} CI file(s){ci.cap_note}",
        at=ci.files[0],
    )


@rule(
    id="CIC005",
    title="Delivery is automated",
    dimension=Dimension.cicd,
    stage=Stage.growth,
    severity=Severity.medium,
    confidence=Confidence.medium,
    description=(
        "A growing customer base needs frequent, repeatable releases; building and shipping "
        "by hand from a laptop does not scale and is a single point of failure."
    ),
    remediation=(
        "Add a workflow that builds and publishes or deploys the product (container image, "
        "package or release) from CI, triggered by a tag, a release or a merge to main."
    ),
)
def delivery_automated(repo: RepoSnapshot) -> Check:
    ci = ci_files(repo)
    if not ci.files:
        return _no_ci("nothing is built, published or deployed automatically")
    found = _first_command(repo, ci, _DELIVERY_COMMANDS)
    if found:
        loc, command = found
        return Check.ok(
            f"CI delivers: `{command}` at {loc.path}:{loc.start_line}{ci.cap_note}",
            evidence=[loc],
        )
    for wf in _workflows(repo, ci):
        triggers = wf.triggers
        push = triggers.get("push")
        on_tag = isinstance(push, dict) and "tags" in push
        if "release" in triggers or "deployment" in triggers or on_tag:
            kind = "tag pushes" if on_tag and "release" not in triggers else "release events"
            return Check.ok(f"{wf.path} is triggered by {kind}", evidence=[wf.path])
    named = _first_command(repo, ci, _DELIVERY_NAMES)
    if named:
        loc, _ = named
        return Check.ok(
            f"A deploy/release/publish job or step is declared at {loc.path}:{loc.start_line}"
            f"{ci.cap_note}",
            evidence=[loc],
        )
    return Check.fail(
        f"No build/publish/deploy/release step found in {len(ci.files)} CI file(s){ci.cap_note}",
        at=ci.files[0],
    )


@rule(
    id="CIC006",
    title="Third-party actions pinned to a commit SHA",
    dimension=Dimension.cicd,
    stage=Stage.maturity,
    severity=Severity.medium,
    confidence=Confidence.high,
    description=(
        "A tag or branch on someone else's action can be moved to malicious code at any time "
        "(as in the tj-actions/changed-files compromise); an established product governs its "
        "supply chain by pinning to immutable commits."
    ),
    remediation=(
        "Replace `uses: owner/action@v1` with the full 40-character commit SHA and keep the "
        "version in a trailing comment; let Dependabot or Renovate update the pins."
    ),
)
def actions_pinned(repo: RepoSnapshot) -> Check:
    ci = ci_files(repo)
    if not ci.workflows:
        return Check.na("No GitHub Actions workflows")
    hits: list[Hit] = []
    total = pinned = first_party_tags = 0
    for path in ci.workflows:
        for no, line in code_lines(repo, path):
            m = _USES_RE.match(line)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith(("./", "../")) or "${{" in ref:
                continue
            total += 1
            if ref.startswith("docker://"):
                if "@sha256:" in ref:
                    pinned += 1
                else:
                    hits.append(Hit(path, f"Container action `{ref}` is not pinned by digest", no))
                continue
            target, _, version = ref.partition("@")
            if _SHA_RE.match(version):
                pinned += 1
            elif target.split("/")[0].lower() in FIRST_PARTY_OWNERS:
                if _VERSION_TAG_RE.match(version):
                    first_party_tags += 1
                else:
                    hits.append(
                        Hit(
                            path,
                            f"First-party action `{ref}` tracks a mutable ref, not a release tag",
                            no,
                            severity=Severity.low,
                            confidence=Confidence.medium,
                        )
                    )
            else:
                shown = version or "no ref"
                hits.append(
                    Hit(path, f"`{target}` is pinned to `{shown}`, not a full commit SHA", no)
                )
    facts = (
        f"{total} action reference(s): {pinned} SHA/digest-pinned, "
        f"{first_party_tags} first-party on a version tag (allowed)"
    )
    if not hits:
        return Check.ok(f"{facts}{ci.cap_note}", evidence=list(ci.workflows[:3]))
    count = len(hits)
    hits, note = _capped(hits)
    return Check.fail(f"{count} unpinned action reference(s) out of {facts}{note}", hits=hits)


@rule(
    id="CIC007",
    title="Workflow token permissions are least-privilege",
    dimension=Dimension.cicd,
    stage=Stage.maturity,
    severity=Severity.medium,
    confidence=Confidence.high,
    description=(
        "Without a `permissions:` block GITHUB_TOKEN may get the repository's broad default "
        "scopes, so one compromised step can push code or publish releases. Governing an "
        "established product means every workflow declares the access it needs."
    ),
    remediation=(
        "Add `permissions: contents: read` at the top of each workflow and grant extra scopes "
        "per job only where needed; never use `permissions: write-all`."
    ),
)
def token_permissions(repo: RepoSnapshot) -> Check:
    ci = ci_files(repo)
    if not ci.workflows:
        return Check.na("No GitHub Actions workflows")
    workflows = _workflows(repo, ci)
    parsed = [w for w in workflows if w.doc is not None]
    if not parsed:
        return Check.na(f"None of the {len(workflows)} GitHub workflow(s) could be parsed")
    write_all = re.compile(r"^\s*permissions:\s*['\"]?write-all['\"]?\s*(?:#.*)?$")
    hits: list[Hit] = []
    for wf in parsed:
        assert wf.doc is not None  # narrowed by the filter above
        top = wf.doc.get("permissions")
        scopes = [top] + [job.get("permissions") for job in wf.jobs.values()]
        if "write-all" in scopes:
            hits.append(
                Hit(wf.path, "`permissions: write-all` grants every scope", wf.line_of(write_all))
            )
            continue
        if top is not None:
            continue
        missing = sorted(name for name, job in wf.jobs.items() if job.get("permissions") is None)
        if missing:
            job_line = re.compile(rf"^\s+['\"]?{re.escape(missing[0])}['\"]?\s*:\s*(?:#.*)?$")
            hits.append(
                Hit(
                    wf.path,
                    "No top-level `permissions:` and none on job(s): " + ", ".join(missing[:5]),
                    wf.line_of(job_line),
                )
            )
    if not hits:
        return Check.ok(
            f"All {len(parsed)} workflow(s) restrict GITHUB_TOKEN permissions"
            f"{_unparsed_note(workflows)}{ci.cap_note}",
            evidence=[w.path for w in parsed[:3]],
        )
    count = len(hits)
    hits, note = _capped(hits)
    return Check.fail(
        f"{count} of {len(parsed)} workflow(s) do not restrict GITHUB_TOKEN permissions{note}",
        hits=hits,
    )


@rule(
    id="CIC008",
    title="No script injection in workflow run steps",
    dimension=Dimension.cicd,
    stage=Stage.stabilization,
    severity=Severity.high,
    confidence=Confidence.high,
    description=(
        "`${{ }}` is expanded before the shell runs, so an attacker-controlled value such as "
        "a pull-request title becomes part of the script and can run arbitrary commands with "
        "the workflow's secrets. As soon as CI exists it must not be remotely exploitable."
    ),
    remediation=(
        "Pass the value through an environment variable (`env: TITLE: ${{ "
        'github.event.pull_request.title }}`) and reference it as "$TITLE" in the script.'
    ),
    weight=1.5,
    tags=("security",),
)
def no_script_injection(repo: RepoSnapshot) -> Check:
    ci = ci_files(repo)
    if not ci.workflows:
        return Check.na("No GitHub Actions workflows")
    hits: list[Hit] = []
    scanned = 0
    for path in ci.workflows:
        for no, text in _run_blocks(tuple(repo.read_lines(path))):
            scanned += 1
            for expr in _EXPR_RE.findall(text):
                ctx = _UNTRUSTED_CONTEXT.search(expr)
                if ctx and not _BOOLEAN_EXPR.search(expr):
                    hits.append(
                        Hit(
                            path,
                            f"Untrusted `{ctx.group(0)}` is interpolated directly into a "
                            "run script",
                            no,
                        )
                    )
    if not hits:
        return Check.ok(
            f"No untrusted event fields interpolated in {scanned} run-script line(s) across "
            f"{len(ci.workflows)} workflow(s){ci.cap_note}",
            evidence=list(ci.workflows[:3]),
        )
    count = len(hits)
    hits, note = _capped(hits)
    return Check.fail(
        f"{count} untrusted expression(s) interpolated into run scripts{note}", hits=hits
    )


@rule(
    id="CIC009",
    title="pull_request_target does not check out untrusted code",
    dimension=Dimension.cicd,
    stage=Stage.stabilization,
    severity=Severity.high,
    confidence=Confidence.medium,
    description=(
        "`pull_request_target` runs with the base repository's secrets and a write token. "
        "Checking out the pull request's head there executes a fork's code with those "
        "privileges (a 'pwn request')."
    ),
    remediation=(
        "Use the `pull_request` trigger for anything that builds or tests PR code. Keep "
        "`pull_request_target` for labelling/commenting only and never check out the PR head "
        "in it."
    ),
    weight=1.5,
    tags=("security",),
)
def no_pwn_request(repo: RepoSnapshot) -> Check:
    ci = ci_files(repo)
    if not ci.workflows:
        return Check.na("No GitHub Actions workflows")
    workflows = _workflows(repo, ci)
    targets = [w for w in workflows if "pull_request_target" in w.triggers]
    if not targets:
        return Check.ok(
            f"None of the {len(workflows)} workflow(s) uses pull_request_target"
            f"{_unparsed_note(workflows)}{ci.cap_note}",
            evidence=list(ci.workflows[:3]),
        )
    ref_line = re.compile(r"^\s*(?:-\s+)?ref:\s*(.*)$")
    hits: list[Hit] = []
    for wf in targets:
        for no, line in enumerate(wf.lines, start=1):
            m = ref_line.match(line)
            if m and _PR_HEAD_REF.search(m.group(1)):
                hits.append(
                    Hit(wf.path, "pull_request_target workflow checks out the PR head ref", no)
                )
        for no, text in _run_blocks(wf.lines):
            if _PR_HEAD_FETCH.search(text):
                hits.append(
                    Hit(wf.path, "pull_request_target workflow fetches the PR head in a script", no)
                )
    if not hits:
        return Check.ok(
            f"{len(targets)} pull_request_target workflow(s) never check out the PR head",
            evidence=[w.path for w in targets[:3]],
        )
    count = len(hits)
    hits, note = _capped(hits)
    return Check.fail(
        f"{count} checkout(s) of untrusted PR code under pull_request_target{note}", hits=hits
    )
