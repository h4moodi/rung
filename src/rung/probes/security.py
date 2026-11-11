"""Security probe: committed secrets, dependency hygiene and security governance.

Every rule is a pure function of the snapshot. There are no network calls, so known-CVE
lookups against vulnerability databases are deliberately out of scope (they would make
the same commit produce different reports on different days).
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import PurePosixPath

from rung.collect import RepoSnapshot
from rung.models import Check, Confidence, Dimension, Hit, Severity, Stage
from rung.probes import _deps, _secrets
from rung.probes._secrets import SecretMatch, confidence_for, is_placeholder, is_reference
from rung.registry import rule

MAX_HITS = 200
HISTORY_MAX_COMMITS = 500
LARGE_BINARY_BYTES = 5_000_000
MAX_ENV_FILE_LINES = 2000

_SEC = Dimension.security


def _capped(count: int) -> str:
    return f" (showing the first {MAX_HITS})" if count > MAX_HITS else ""


def _describe(match: SecretMatch) -> str:
    detail = f", {match.detail}" if match.detail else ""
    return f"{match.kind}{detail} [{match.preview}]"


# ------------------------------------------------------------------------- secrets


@rule(
    id="SEC001",
    title="No provider credentials in the working tree",
    dimension=_SEC,
    stage=Stage.inception,
    severity=Severity.critical,
    confidence=Confidence.high,
    weight=3.0,
    tags=("secrets",),
    description=(
        "API keys, tokens and private keys committed to the repository are readable by "
        "everyone with access to it and are harvested by bots within minutes on public hosts."
    ),
    remediation=(
        "Rotate the credential first (assume it is compromised), then remove it from the code, "
        "load it from the environment or a secret manager, and purge it from git history."
    ),
)
def no_provider_credentials(repo: RepoSnapshot) -> Check:
    scan = _secrets.scan_tree(repo)
    matches = [m for m in scan.provider if not m.key_file]
    note = "; scan stopped early at the match limit" if scan.truncated else ""
    if not matches:
        return Check.ok(
            f"No provider-format credentials in {scan.files_scanned} text files scanned{note}"
        )
    hits = [
        Hit(
            path=m.path,
            line=m.line,
            message=f"{_describe(m)} is committed: treat it as compromised and rotate it",
            severity=m.severity,
            confidence=m.confidence,
        )
        for m in matches[:MAX_HITS]
    ]
    files = len({m.path for m in matches})
    return Check.fail(
        f"{len(matches)} credential(s) in {files} file(s){_capped(len(matches))}{note}", hits
    )


@rule(
    id="SEC002",
    title="No generic hard-coded secrets",
    dimension=_SEC,
    stage=Stage.inception,
    severity=Severity.medium,
    confidence=Confidence.low,
    tags=("secrets",),
    description=(
        "Passwords and keys assigned as string literals end up in every clone, build and "
        "log, and cannot be rotated without a code change."
    ),
    remediation=(
        "Read the value from an environment variable or secret manager; rotate it if it was "
        "ever real."
    ),
)
def no_generic_secrets(repo: RepoSnapshot) -> Check:
    scan = _secrets.scan_tree(repo)
    if not scan.generic:
        return Check.ok(f"No hard-coded secret assignments in {scan.files_scanned} text files")
    hits = [
        Hit(
            path=m.path,
            line=m.line,
            message=f"Literal assigned to a '{m.detail}' name [{m.preview}]: looks hard-coded",
            confidence=m.confidence,
        )
        for m in scan.generic[:MAX_HITS]
    ]
    count = len(scan.generic)
    return Check.fail(f"{count} possible hard-coded secret(s){_capped(count)}", hits)


_KEY_NAMES = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})
_KEYSTORE_SUFFIXES = (".p12", ".pfx", ".jks", ".keystore")
_PRIVATE_KEY_MARKERS = ("PRIVATE KEY-----", "PRIVATE KEY BLOCK-----", "PuTTY-User-Key-File")


@rule(
    id="SEC003",
    title="No private keys or keystores committed",
    dimension=_SEC,
    stage=Stage.inception,
    severity=Severity.critical,
    confidence=Confidence.high,
    weight=3.0,
    tags=("secrets",),
    description=(
        "A committed private key lets anyone with repository access impersonate the server, "
        "user or signing identity it belongs to."
    ),
    remediation=(
        "Revoke and regenerate the key pair, delete the file, add its pattern to .gitignore "
        "and purge it from git history."
    ),
)
def no_private_key_files(repo: RepoSnapshot) -> Check:
    hits = []
    for path in repo.files:
        name = PurePosixPath(path).name.lower()
        if name.endswith(_KEYSTORE_SUFFIXES):
            if repo.size(path) == 0:
                continue
            kind = "Keystore file"
            confidence = Confidence.low if name == "debug.keystore" else Confidence.medium
        elif name in _KEY_NAMES or name.endswith((".pem", ".key", ".ppk")):
            text = repo.read_text(path) or ""
            if not any(marker in text for marker in _PRIVATE_KEY_MARKERS):
                continue  # public certificate, empty stub or unreadable binary
            kind, confidence = "Private key file", Confidence.high
        else:
            continue
        hits.append(
            Hit(
                path=path,
                message=f"{kind} is committed: revoke the key and remove the file",
                confidence=confidence_for(path, confidence),
            )
        )
    if not hits:
        return Check.ok("No private key or keystore files are tracked")
    return Check.fail(f"{len(hits)} private key/keystore file(s) tracked", hits[:MAX_HITS])


_ENV_TEMPLATE_PARTS = frozenset(
    {"example", "sample", "template", "dist", "defaults", "default", "tmpl", "tpl", "schema"}
)
_ENV_SHARED_PARTS = frozenset({"development", "dev", "test", "testing", "ci"})
_ENV_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=\s*(.*)$")


def _env_suffix_parts(path: str) -> list[str] | None:
    """Suffix parts of a real env file name (``.env.local`` -> ['local']); None otherwise."""
    name = PurePosixPath(path).name.lower()
    if name != ".env" and not name.startswith(".env."):
        return None
    parts = [p for p in name[5:].split(".") if p]
    return None if any(p in _ENV_TEMPLATE_PARTS for p in parts) else parts


def _env_assignments(repo: RepoSnapshot, path: str) -> int:
    count = 0
    for line in repo.read_lines(path)[:MAX_ENV_FILE_LINES]:
        m = _ENV_ASSIGN_RE.match(line)
        if m is None:
            continue
        value = m.group(1).split(" #", 1)[0].strip().strip("\"'")
        if value and not is_placeholder(value) and not is_reference(value):
            count += 1
    return count


@rule(
    id="SEC004",
    title="No environment files committed",
    dimension=_SEC,
    stage=Stage.inception,
    severity=Severity.high,
    confidence=Confidence.high,
    weight=2.0,
    tags=("secrets",),
    description=(
        ".env files hold per-deployment configuration, usually including database passwords "
        "and API keys; committing one publishes those values to every clone."
    ),
    remediation=(
        "Rotate any real values, remove the file from version control (git rm --cached), "
        "ignore it in .gitignore and commit a .env.example with placeholders instead."
    ),
)
def no_env_files(repo: RepoSnapshot) -> Check:
    hits = []
    for path in repo.files:
        parts = _env_suffix_parts(path)
        if parts is None:
            continue
        count = _env_assignments(repo, path)
        if count == 0:
            continue
        shared = any(p in _ENV_SHARED_PARTS for p in parts)
        hits.append(
            Hit(
                path=path,
                message=f"Environment file with {count} assigned value(s) is committed",
                confidence=confidence_for(path, Confidence.medium if shared else Confidence.high),
            )
        )
    if not hits:
        return Check.ok("No populated .env files are tracked")
    return Check.fail(f"{len(hits)} environment file(s) with values tracked", hits[:MAX_HITS])


@rule(
    id="SEC005",
    title="No credentials left in git history",
    dimension=_SEC,
    stage=Stage.inception,
    severity=Severity.high,
    confidence=Confidence.medium,
    weight=2.0,
    tags=("secrets", "history"),
    description=(
        "Deleting a credential in a later commit does not unpublish it: it stays readable in "
        "history for anyone who clones the repository."
    ),
    remediation=(
        "Rotate the credential first; then rewrite history (git filter-repo or BFG) and "
        "force-push if the value must be removed from the repository."
    ),
)
def no_secrets_in_history(repo: RepoSnapshot) -> Check:
    if not repo.is_git or repo.head is None:
        return Check.na("Not a git repository with commits: no history to scan")
    history = _secrets.scan_history(repo, HISTORY_MAX_COMMITS)
    notes = ""
    if repo.commit_count > HISTORY_MAX_COMMITS:
        notes += f"; only the newest {HISTORY_MAX_COMMITS} of {repo.commit_count} commits scanned"
    if repo.is_shallow:
        notes += "; shallow clone, older history not visible"
    scope = f"{history.lines_scanned} added line(s) of history"
    if not history.matches:
        return Check.ok(f"No removed credentials found in {scope}{notes}")
    hits = [
        Hit(
            path=m.path,
            message=(
                f"{m.kind} was added at line {m.line} in commit {m.sha[:8]} and is no longer "
                "in the working tree, but remains exposed in history"
            ),
            confidence=m.confidence,
        )
        for m in history.matches[:MAX_HITS]
    ]
    count = len(history.matches)
    return Check.fail(f"{count} credential(s) in {scope}{_capped(count)}{notes}", hits)


_DOTENV_HINT_RE = re.compile(
    r"dotenv|django-environ|python-decouple|pydantic-settings|env_file", re.IGNORECASE
)
_HINT_FILES = (
    "requirements.txt", "pyproject.toml", "Pipfile", "package.json", "Gemfile",
    "composer.json", "go.mod", "Cargo.toml", "docker-compose.yml", "docker-compose.yaml",
    "compose.yml", "compose.yaml",
)  # fmt: skip


def _gitignore_covers_env(lines: list[str]) -> bool:
    covered = False
    for raw in lines:
        pattern = raw.strip()
        if not pattern or pattern.startswith("#"):
            continue
        negated = pattern.startswith("!")
        pattern = pattern.lstrip("!").removeprefix("**/").removeprefix("/")
        if not pattern.endswith("/") and fnmatch.fnmatchcase(".env", pattern):
            covered = not negated
    return covered


@rule(
    id="SEC006",
    title=".gitignore covers environment files",
    dimension=_SEC,
    stage=Stage.inception,
    severity=Severity.low,
    confidence=Confidence.medium,
    weight=0.5,
    tags=("secrets",),
    description=(
        "Without an ignore pattern for .env, the first 'git add .' commits local credentials."
    ),
    remediation="Add '.env' (and '.env.*' with '!.env.example') to .gitignore.",
)
def gitignore_covers_env(repo: RepoSnapshot) -> Check:
    if not repo.exists(".gitignore"):
        return Check.na("No root .gitignore (reported by the documentation probe)")
    env_files = [f for f in repo.files if PurePosixPath(f).name.lower().startswith(".env")]
    hints = [
        f for f in repo.find_named(*_HINT_FILES) if _DOTENV_HINT_RE.search(repo.read_text(f) or "")
    ]
    if not env_files and not hints:
        return Check.na("No sign of .env / dotenv usage in this repository")
    if _gitignore_covers_env(repo.read_lines(".gitignore")):
        return Check.ok(".gitignore has a pattern covering .env", evidence=[".gitignore"])
    sign = (env_files + hints)[0]
    return Check.fail(
        f".gitignore has no pattern covering .env although the repo uses env files ({sign})",
        at=".gitignore",
    )


# -------------------------------------------------------------------- dependencies


@rule(
    id="SEC007",
    title="Dependencies declared in a manifest",
    dimension=_SEC,
    stage=Stage.inception,
    severity=Severity.medium,
    confidence=Confidence.medium,
    tags=("dependencies",),
    description=(
        "Without a manifest nobody (including scanners) can tell which third-party code the "
        "project runs, so it cannot be installed reproducibly or checked for vulnerabilities."
    ),
    remediation=(
        "Declare dependencies in the ecosystem's manifest (pyproject.toml, package.json, ...)."
    ),
)
def dependency_manifest_present(repo: RepoSnapshot) -> Check:
    manifests = _deps.find_manifests(repo)
    if manifests:
        return Check.ok(f"{len(manifests)} dependency manifest(s) found", evidence=manifests[:5])
    sources = _deps.source_files(repo)
    if not sources:
        return Check.na("No recognisable source code")
    return Check.fail(f"{len(sources)} source file(s) but no dependency manifest", at=sources[0])


@rule(
    id="SEC008",
    title="Lockfile committed for each dependency manifest",
    dimension=_SEC,
    stage=Stage.stabilization,
    severity=Severity.medium,
    confidence=Confidence.medium,
    tags=("dependencies",),
    description=(
        "A lockfile pins the exact dependency tree, so the build that was tested is the build "
        "that ships and a hijacked upstream release is not picked up silently."
    ),
    remediation="Generate the ecosystem's lockfile and commit it next to the manifest.",
)
def lockfiles_present(repo: RepoSnapshot) -> Check:
    units = _deps.lock_units(repo)
    if not units:
        return Check.na("No manifest belonging to an ecosystem with a lockfile")
    missing = [u for u in units if u.lockfile is None]
    if not missing:
        locks = sorted({u.lockfile for u in units if u.lockfile})
        return Check.ok(f"All {len(units)} manifest(s) are locked", evidence=locks[:5])
    hits = [
        Hit(
            path=u.manifest,
            message=f"No lockfile for this manifest (expected {u.expected})",
            confidence=u.confidence,
        )
        for u in missing[:MAX_HITS]
    ]
    return Check.fail(f"{len(missing)} of {len(units)} manifest(s) have no lockfile", hits)


@rule(
    id="SEC009",
    title="No unpinned or wildcard dependency versions",
    dimension=_SEC,
    stage=Stage.growth,
    severity=Severity.low,
    confidence=Confidence.medium,
    tags=("dependencies",),
    description=(
        "A dependency with no version constraint installs whatever is newest, so builds "
        "change without a commit and a malicious release is adopted automatically."
    ),
    remediation="Give every dependency a version constraint (and commit a lockfile).",
)
def no_unpinned_dependencies(repo: RepoSnapshot) -> Check:
    hits: list[Hit] = []
    checked = 0
    for path in _deps.find_manifests(repo):
        name = PurePosixPath(path).name.lower()
        lines = repo.read_lines(path)
        if name.startswith("requirements"):
            for req in _deps.parse_requirements(lines):
                checked += 1
                if not req.has_specifier:
                    hits.append(Hit(path, f"'{req.name}' has no version specifier", line=req.line))
        elif name == "package.json":
            for dep, spec in sorted(_deps.package_json_deps(repo, path).items()):
                checked += 1
                if _deps.is_unpinned_js_spec(spec):
                    needle = f'"{dep}"'
                    line = next((n for n, t in enumerate(lines, 1) if needle in t), None)
                    hits.append(Hit(path, f"'{dep}' accepts any version ('{spec}')", line=line))
    if checked == 0:
        return Check.na("No requirements.txt or package.json dependencies to check")
    if not hits:
        return Check.ok(f"All {checked} declared dependencies have a version constraint")
    return Check.fail(
        f"{len(hits)} of {checked} dependencies are unpinned{_capped(len(hits))}", hits[:MAX_HITS]
    )


_UPDATE_BOT_GLOBS = (
    ".github/dependabot.yml", ".github/dependabot.yaml", ".gitlab/dependabot*", "renovate.json",
    "renovate.json5", ".renovaterc", ".renovaterc.json", ".renovaterc.json5",
    ".github/renovate.json", ".github/renovate.json5", ".gitlab/renovate.json", ".pyup.yml",
)  # fmt: skip


@rule(
    id="SEC011",
    title="Dependency update automation configured",
    dimension=_SEC,
    stage=Stage.growth,
    severity=Severity.low,
    confidence=Confidence.medium,
    tags=("dependencies",),
    description=(
        "Once a team and its dependency tree grow, manual upgrades fall behind; automated "
        "update PRs keep security fixes flowing. (Hosted bots configured only in a web UI "
        "are invisible to rung.)"
    ),
    remediation="Add .github/dependabot.yml or a Renovate configuration.",
)
def dependency_updates_automated(repo: RepoSnapshot) -> Check:
    if not _deps.find_manifests(repo):
        return Check.na("No dependency manifest, nothing to keep updated")
    found = repo.glob(*_UPDATE_BOT_GLOBS)
    if not found and repo.exists("package.json"):
        if re.search(r'^\s*"renovate"\s*:', repo.read_text("package.json") or "", re.MULTILINE):
            found = ["package.json"]
    if found:
        return Check.ok(f"Dependency update automation configured in {found[0]}", evidence=found)
    return Check.fail("No Dependabot or Renovate configuration found", at=".github/dependabot.yml")


# ---------------------------------------------------------------------- governance


@rule(
    id="SEC012",
    title="Security policy present",
    dimension=_SEC,
    stage=Stage.maturity,
    severity=Severity.low,
    confidence=Confidence.high,
    tags=("governance",),
    description=(
        "An established product needs a documented, private channel for vulnerability "
        "reports; without one, researchers file public issues or stay silent."
    ),
    remediation="Add a SECURITY.md describing supported versions and how to report privately.",
)
def security_policy_present(repo: RepoSnapshot) -> Check:
    found = [
        f
        for f in repo.glob("SECURITY.*", "SECURITY", "docs/SECURITY.*", ".github/SECURITY.*")
        if repo.size(f) > 0
    ]
    if found:
        return Check.ok(f"Security policy found at {found[0]}", evidence=found[:1])
    return Check.fail("No SECURITY.md in the root, docs/ or .github/", at="SECURITY.md")


_CI_GLOBS = (
    ".github/workflows/*.yml", ".github/workflows/*.yaml", ".gitlab-ci.yml", ".circleci/config.yml",
    "azure-pipelines.yml", "bitbucket-pipelines.yml", "Jenkinsfile", ".travis.yml", ".drone.yml",
    ".pre-commit-config.yaml", ".pre-commit-config.yml",
)  # fmt: skip
_SCANNER_RE = re.compile(
    r"codeql|gitleaks|trufflehog|detect-secrets|semgrep|\bbandit\b|trivy|\bgrype\b|\bsnyk\b"
    r"|osv-scanner|(?:npm|yarn|pnpm) audit|pip-audit|cargo[ -](?:audit|deny)|gosec|govulncheck"
    r"|dependency-review-action|scorecard-action|bundler-audit|brakeman|checkov|tfsec",
    re.IGNORECASE,
)


@rule(
    id="SEC013",
    title="Automated security scanning in CI or pre-commit",
    dimension=_SEC,
    stage=Stage.maturity,
    severity=Severity.medium,
    confidence=Confidence.medium,
    tags=("governance",),
    description=(
        "A mature product cannot rely on reviewers to spot vulnerable dependencies, leaked "
        "secrets or insecure code; a scanner in the pipeline checks every change. (Scanning "
        "enabled only in the hosting platform's settings is invisible to rung.)"
    ),
    remediation=("Add a scanner to CI or pre-commit, e.g. CodeQL, gitleaks, semgrep or pip-audit."),
)
def security_scanning_configured(repo: RepoSnapshot) -> Check:
    configs = repo.glob(*_CI_GLOBS)
    for path in configs:
        for no, line in enumerate(repo.read_lines(path), start=1):
            m = None if line.lstrip().startswith("#") else _SCANNER_RE.search(line)
            if m:
                return Check.ok(
                    f"Security scanner '{m.group(0).lower()}' configured in {path}:{no}",
                    evidence=[path],
                )
    if configs:
        return Check.fail(
            f"No security scanner found in {len(configs)} CI/pre-commit file(s)", at=configs[0]
        )
    return Check.fail(
        "No CI or pre-commit configuration, so no automated security scanning",
        at=".github/workflows",
    )


_ASSET_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".psd", ".ttf",
    ".otf", ".woff", ".woff2", ".eot", ".pdf", ".mp4", ".mov", ".webm", ".mp3", ".wav", ".ogg",
)  # fmt: skip


@rule(
    id="SEC014",
    title="No large binary blobs tracked",
    dimension=_SEC,
    stage=Stage.stabilization,
    severity=Severity.low,
    confidence=Confidence.medium,
    weight=0.5,
    tags=("hygiene",),
    description=(
        "Large tracked binaries bloat every clone forever and are usually build artifacts or "
        "vendored executables that cannot be reviewed or scanned."
    ),
    remediation=(
        "Remove the file, ignore the build output, and publish artifacts via releases, a "
        "package registry or Git LFS."
    ),
)
def no_large_binaries(repo: RepoSnapshot) -> Check:
    limit_mb = LARGE_BINARY_BYTES / 1_000_000
    hits = []
    for path in repo.files:
        size = repo.size(path)
        if size <= LARGE_BINARY_BYTES or path.lower().endswith(_ASSET_SUFFIXES):
            continue
        if repo.is_binary(path):
            hits.append(Hit(path, f"Binary file of {size / 1_000_000:.1f} MB is tracked"))
    if not hits:
        return Check.ok(f"No tracked non-asset binary larger than {limit_mb:.0f} MB")
    return Check.fail(
        f"{len(hits)} tracked binary file(s) larger than {limit_mb:.0f} MB", hits[:MAX_HITS]
    )
