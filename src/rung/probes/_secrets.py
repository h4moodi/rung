"""Secret-detection primitives shared by the security rules (not a probe module).

Nothing in here ever stores or returns a raw secret value: a match is reduced, at the
moment it is found, to a redacted preview (:func:`rung.redact.redact`) and a one-way
anchor (:func:`rung.redact.secret_anchor`) used only for de-duplication.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from weakref import WeakKeyDictionary

from rung.collect import AddedLine, RepoSnapshot
from rung.models import Confidence, Severity
from rung.redact import redact, secret_anchor

# --------------------------------------------------------------------------- limits

MAX_SCAN_FILE_BYTES = 1_000_000  # larger files are skipped entirely
MAX_LINE_LENGTH = 2000  # longer lines are minified/generated: skipped
MAX_MATCHES_PER_KIND = 2000  # hard stop for the shared tree scan (per rule family)
GENERIC_MIN_LENGTH = 8
GENERIC_MAX_LENGTH = 200
GENERIC_MIN_ENTROPY = 3.0  # Shannon bits per character
GENERIC_WEAK_KEYWORD_MIN_LENGTH = 12
GENERIC_STRONG_LENGTH = 20

# ------------------------------------------------------------------- path handling

_LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
        "bun.lockb", "poetry.lock", "pdm.lock", "uv.lock", "pipfile.lock", "cargo.lock",
        "go.sum", "gemfile.lock", "composer.lock", "mix.lock", "packages.lock.json",
        "flake.lock", "pubspec.lock", "podfile.lock", "gradle.lockfile", "package.resolved",
    }
)  # fmt: skip
_SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".lock", ".svg")
_DOC_SUFFIXES = (".md", ".mdx", ".markdown", ".rst", ".adoc", ".txt")
_LOW_TRUST_PARTS = frozenset(
    {
        "test", "tests", "testing", "__tests__", "spec", "specs", "fixture", "fixtures",
        "testdata", "test-data", "test_data", "mock", "mocks", "__mocks__", "doc", "docs",
        "documentation", "example", "examples", "sample", "samples", "demo", "demos", "e2e",
    }
)  # fmt: skip
_TEST_NAME_RE = re.compile(r"(?:^test_|^conftest\.py$|(?:_test|\.test|\.spec|_spec)\.[a-z0-9]+$)")
_KEY_FILE_NAMES = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})
_KEY_FILE_SUFFIXES = (".pem", ".key", ".ppk")


def is_scannable_path(path: str) -> bool:
    """False for lockfiles, minified bundles and source maps (hash-dense, never hand-written)."""
    name = PurePosixPath(path).name.lower()
    return name not in _LOCKFILE_NAMES and not name.endswith(_SKIP_SUFFIXES)


def is_doc_path(path: str) -> bool:
    return path.lower().endswith(_DOC_SUFFIXES)


def is_low_trust_path(path: str) -> bool:
    """Tests, fixtures, docs and examples: findings there get lower confidence."""
    parts = PurePosixPath(path.lower()).parts
    if not parts:
        return False
    name = parts[-1]
    return (
        any(p in _LOW_TRUST_PARTS for p in parts[:-1])
        or bool(_TEST_NAME_RE.search(name))
        or name.endswith(_DOC_SUFFIXES)
    )


def is_key_file_path(path: str) -> bool:
    """Paths whose private-key content is owned by the key-file rule (SEC003)."""
    name = PurePosixPath(path).name.lower()
    return name in _KEY_FILE_NAMES or name.endswith(_KEY_FILE_SUFFIXES)


_LOWER = {
    Confidence.high: Confidence.medium,
    Confidence.medium: Confidence.low,
    Confidence.low: Confidence.low,
}


def lowered(confidence: Confidence) -> Confidence:
    return _LOWER[confidence]


def confidence_for(path: str, confidence: Confidence) -> Confidence:
    return lowered(confidence) if is_low_trust_path(path) else confidence


# --------------------------------------------------------------- value heuristics

_PLACEHOLDER_RE = re.compile(
    r"example|sample|dummy|placeholder|change[_-]?me|your[_-]|xxxx|<[^>]*>|\$\{|\{\{"
    r"|replace[_-]?me|redacted|fake|foobar|\*{3,}|\.{3,}|1234567|abcdefg",
    re.IGNORECASE,
)
_REFERENCE_RE = re.compile(
    r"^\$|\$\(|\{[^}]*\}|%s|%d|%\(|#\{|^<.*>$|process\.env|os\.environ|getenv|ENV\[", re.IGNORECASE
)
_PATHLIKE_RE = re.compile(
    r"^(?:/|\./|\.\./|~/|[a-z][a-z0-9+.\-]*://|file:)"
    r"|\.(?:pem|key|json|ya?ml|txt|crt|cer|p12|pfx|env|ini|conf|cfg|toml|properties|py|js|ts)$",
    re.IGNORECASE,
)
_KEYWORD_IN_VALUE_RE = re.compile(r"pass|secret|token|key|auth|credential", re.IGNORECASE)


def is_placeholder(value: str) -> bool:
    """Template values, documentation keys (``...EXAMPLE``) and one-character fillers."""
    return (len(value) >= 4 and len(set(value)) == 1) or bool(_PLACEHOLDER_RE.search(value))


def is_reference(value: str) -> bool:
    """The value is read from somewhere else (env var, template, format string)."""
    return bool(_REFERENCE_RE.search(value))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in Counter(value).values())


def _char_classes(value: str) -> int:
    """How many of lower / upper / digit / punctuation occur (``_ - .`` do not count)."""
    return (
        any(c.islower() for c in value)
        + any(c.isupper() for c in value)
        + any(c.isdigit() for c in value)
        + any(not c.isalnum() and c not in "_-." for c in value)
    )


# ------------------------------------------------------------------------ patterns


@dataclass(frozen=True)
class SecretPattern:
    """One provider credential format.

    ``needles`` are literal substrings, at least one of which every match contains: they
    make the per-file and per-line pre-filter a plain substring test.
    ``keep`` is how many leading characters are a public format prefix and safe to show.
    """

    kind: str
    regex: re.Pattern[str]
    needles: tuple[str, ...]
    confidence: Confidence = Confidence.high
    severity: Severity | None = None
    keep: int = 4
    in_history: bool = True
    group: int = 0


def _p(
    kind: str,
    regex: str,
    needles: Sequence[str],
    confidence: Confidence = Confidence.high,
    *,
    severity: Severity | None = None,
    keep: int = 4,
    in_history: bool = True,
) -> SecretPattern:
    return SecretPattern(
        kind, re.compile(regex), tuple(needles), confidence, severity, keep, in_history
    )


_END = r"(?![A-Za-z0-9_\-])"

#: Ordered most specific first: a later pattern never re-reports an overlapping span.
PROVIDER_PATTERNS: tuple[SecretPattern, ...] = (
    _p("AWS access key ID", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", ("AKIA", "ASIA")),
    _p(
        "GitHub fine-grained personal access token",
        r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b",
        ("github_pat_",),
    ),
    _p(
        "GitHub token",
        r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    ),
    _p("GitLab personal access token", r"\bglpat-[A-Za-z0-9_\-]{20,}" + _END, ("glpat-",)),
    _p(
        "Slack webhook URL",
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9]{6,}/B[A-Za-z0-9]{6,}/[A-Za-z0-9]{20,}",
        ("hooks.slack.com/services/",),
        keep=0,
    ),
    _p(
        "Slack token",
        r"\bxox[baprs]-[0-9A-Za-z]{8,}(?:-[0-9A-Za-z]{4,}){1,4}" + _END,
        ("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"),
    ),
    _p("Stripe live secret key", r"\b[sr]k_live_[A-Za-z0-9]{20,}\b", ("sk_live_", "rk_live_")),
    _p("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}" + _END, ("AIza",)),
    _p(
        "SendGrid API key",
        r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}" + _END,
        ("SG.",),
        keep=3,
    ),
    _p("npm access token", r"\bnpm_[A-Za-z0-9]{36}\b", ("npm_",)),
    _p("PyPI upload token", r"\bpypi-AgE[A-Za-z0-9_\-]{60,}" + _END, ("pypi-AgE",)),
    _p(
        "Anthropic API key",
        r"\bsk-ant-[A-Za-z0-9]{2,12}-[A-Za-z0-9_\-]{40,}" + _END,
        ("sk-ant-",),
        keep=3,
    ),
    _p(
        "OpenAI API key",
        r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"
        + _END,
        ("sk-",),
        keep=3,
    ),
    _p(
        "API secret key (sk- format)",
        r"(?<![A-Za-z0-9_\-])sk-[A-Za-z0-9]{40,}" + _END,
        ("sk-",),
        Confidence.medium,
        keep=3,
    ),
    _p("Twilio API key", r"\bSK[0-9a-f]{32}\b", ("SK",), Confidence.medium, keep=2),
    _p(
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}" + _END,
        ("eyJ",),
        Confidence.low,
        severity=Severity.medium,
        keep=3,
        in_history=False,
    ),
)

PEM_KIND = "Private key (PEM block)"
_PEM_NEEDLE = "PRIVATE KEY"
_PEM_HEADER_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_PEM_INLINE_BODY_RE = re.compile(r"""(?:\\r|\\n|[\s"'+])*([A-Za-z0-9+/=]{40,})""")
_PEM_NEXT_BODY_RE = re.compile(
    r"""^[\s"'+]*(?:([A-Za-z0-9+/=]{40,})|((?:Proc-Type|DEK-Info|Version|Comment):.*))"""
)

BASIC_AUTH_KIND = "URL with embedded credentials"
_BASIC_AUTH_NEEDLE = "://"
_BASIC_AUTH_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9+.\-]{1,15})://([^\s:/@'\"<>`,]{1,64}):([^\s/@'\"<>`,]{3,128})@"
    r"([A-Za-z0-9.\-]+)"
)
_DEFAULT_PASSWORDS = frozenset(
    {
        "password", "passwd", "pass", "pwd", "secret", "postgres", "root", "admin", "user",
        "guest", "test", "mysql", "mongo", "redis", "rabbitmq", "docker", "default", "dev",
        "toor", "qwerty", "letmein",
    }
)  # fmt: skip
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal"})  # noqa: S104

_GENERIC_KEYWORDS = ("passw", "passphrase", "pwd", "secret", "key", "token", "auth", "credential")
_GENERIC_RE = re.compile(
    rf"""(?ix)
    (?<![A-Za-z0-9])
    [A-Za-z0-9_.\-]{{0,40}}?
    (?P<kw>
        (?P<strong>password|passwd|passphrase|secret(?:[_-]?key)?|api[_-]?key|access[_-]?key
            |private[_-]?key|client[_-]?secret|auth[_-]?token)
      | token | auth | pwd | credentials?
    )
    ["']?\s*(?:=>|:=|=|:)\s*
    (?P<q>["'])(?P<value>[^"'\s]{{{GENERIC_MIN_LENGTH},{GENERIC_MAX_LENGTH}}})(?P=q)
    """
)
GENERIC_KIND = "Hard-coded secret"


@dataclass(frozen=True)
class SecretMatch:
    """A detected credential, already reduced to display-safe fields.

    ``preview`` is redacted, ``anchor`` is a one-way hash used only for de-duplication;
    the raw value is deliberately not kept.
    """

    kind: str
    path: str
    line: int
    preview: str
    anchor: str
    confidence: Confidence
    severity: Severity | None = None
    detail: str = ""
    sha: str = ""
    key_file: bool = False


@dataclass(frozen=True)
class TreeScan:
    """Result of the single shared pass over the working tree."""

    provider: tuple[SecretMatch, ...]
    generic: tuple[SecretMatch, ...]
    files_scanned: int
    truncated: bool

    @property
    def anchors(self) -> frozenset[tuple[str, str]]:
        return frozenset((m.kind, m.anchor) for m in self.provider)


# -------------------------------------------------------------------- line scanners


def _overlaps(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    return any(span[0] < end and start < span[1] for start, end in taken)


def scan_line_provider(
    path: str,
    line_no: int,
    line: str,
    next_line: str | None,
    patterns: Iterable[SecretPattern] = PROVIDER_PATTERNS,
    *,
    pem: bool = True,
    basic_auth: bool = True,
) -> Iterator[SecretMatch]:
    """Provider-format credentials on one line. ``next_line`` confirms PEM blocks."""
    if len(line) > MAX_LINE_LENGTH:
        return
    taken: list[tuple[int, int]] = []
    for pattern in patterns:
        if not any(n in line for n in pattern.needles):
            continue
        for m in pattern.regex.finditer(line):
            value = m.group(pattern.group)
            if _overlaps(m.span(), taken) or is_placeholder(value):
                continue
            taken.append(m.span())
            yield SecretMatch(
                kind=pattern.kind,
                path=path,
                line=line_no,
                preview=redact(value, keep=pattern.keep),
                anchor=secret_anchor(value),
                confidence=confidence_for(path, pattern.confidence),
                severity=pattern.severity,
            )
    if pem and _PEM_NEEDLE in line:
        yield from _scan_pem(path, line_no, line, next_line)
    if basic_auth and _BASIC_AUTH_NEEDLE in line and "@" in line:
        yield from _scan_basic_auth(path, line_no, line, taken)


def _scan_pem(path: str, line_no: int, line: str, next_line: str | None) -> Iterator[SecretMatch]:
    """A PRIVATE KEY header counts only when key material follows it.

    That keeps parsers, detectors and docs that merely mention the header out of the report.
    """
    header = _PEM_HEADER_RE.search(line)
    if header is None:
        return
    inline = _PEM_INLINE_BODY_RE.match(line, header.end())
    body = inline.group(1) if inline and inline.group(1) else None
    if body is None and next_line is not None and len(next_line) <= MAX_LINE_LENGTH:
        following = _PEM_NEXT_BODY_RE.match(next_line)
        if following:
            body = following.group(1) or following.group(2)
    if body is None or is_placeholder(body):
        return
    yield SecretMatch(
        kind=PEM_KIND,
        path=path,
        line=line_no,
        preview="key material redacted",
        anchor=secret_anchor(body),
        confidence=confidence_for(path, Confidence.high),
        key_file=is_key_file_path(path),
    )


def _scan_basic_auth(
    path: str, line_no: int, line: str, taken: list[tuple[int, int]]
) -> Iterator[SecretMatch]:
    for m in _BASIC_AUTH_RE.finditer(line):
        scheme, user, password, host = m.groups()
        if _overlaps(m.span(), taken):
            continue
        if is_placeholder(m.group(0)) or is_reference(password) or is_reference(user):
            continue
        if any(c in password for c in "{}$"):
            continue
        weak = password.lower() in _DEFAULT_PASSWORDS or password == user
        local = host.lower() in _LOCAL_HOSTS or "." not in host
        strong = not (weak or local)
        yield SecretMatch(
            kind=BASIC_AUTH_KIND,
            path=path,
            line=line_no,
            preview=redact(password, keep=0),
            anchor=secret_anchor(f"{user}:{password}@{host}"),
            confidence=confidence_for(path, Confidence.medium) if strong else Confidence.low,
            severity=Severity.high if strong else Severity.low,
            detail=f"{scheme.lower()}:// on host {host}",
        )


def scan_line_generic(path: str, line_no: int, line: str) -> Iterator[SecretMatch]:
    """Keyword assignments of a quoted, random-looking literal (the SEC002 heuristic)."""
    if len(line) > MAX_LINE_LENGTH:
        return
    for m in _GENERIC_RE.finditer(line):
        value = m.group("value")
        strong_keyword = m.group("strong") is not None
        has_digit = any(c.isdigit() for c in value)
        has_alpha = any(c.isalpha() for c in value)
        if is_placeholder(value) or is_reference(value) or _PATHLIKE_RE.search(value):
            continue
        if shannon_entropy(value) < GENERIC_MIN_ENTROPY:
            continue
        if not has_digit and _KEYWORD_IN_VALUE_RE.search(value):
            continue  # "client_secret", "MyPasswordField": a name, not a value
        classes = _char_classes(value)
        if strong_keyword:
            if classes < 2:
                continue
        elif not (has_digit and has_alpha and len(value) >= GENERIC_WEAK_KEYWORD_MIN_LENGTH):
            continue
        looks_random = (classes >= 3 and len(value) >= GENERIC_WEAK_KEYWORD_MIN_LENGTH) or (
            len(value) >= GENERIC_STRONG_LENGTH and has_digit and has_alpha
        )
        confidence = Confidence.medium if strong_keyword and looks_random else Confidence.low
        yield SecretMatch(
            kind=GENERIC_KIND,
            path=path,
            line=line_no,
            preview=redact(value, keep=0),
            anchor=secret_anchor(value),
            confidence=confidence_for(path, confidence),
            detail=m.group("kw").lower(),
        )


# ----------------------------------------------------------------------- tree scan

_SCAN_CACHE: WeakKeyDictionary[RepoSnapshot, TreeScan] = WeakKeyDictionary()


def scan_tree(repo: RepoSnapshot) -> TreeScan:
    """One pass over every text file, shared by SEC001, SEC002 and SEC005.

    Memoised per snapshot object (weakly, so nothing outlives the snapshot and the
    snapshot itself is not mutated). The result is a pure function of the snapshot.
    """
    cached = _SCAN_CACHE.get(repo)
    if cached is None:
        cached = _scan_tree(repo)
        _SCAN_CACHE[repo] = cached
    return cached


def _scan_tree(repo: RepoSnapshot) -> TreeScan:
    provider: list[SecretMatch] = []
    generic: list[SecretMatch] = []
    files_scanned = 0
    truncated = False
    for path in repo.files:
        if not is_scannable_path(path) or repo.size(path) > MAX_SCAN_FILE_BYTES:
            continue
        text = repo.read_text(path, MAX_SCAN_FILE_BYTES)
        if text is None:
            continue
        files_scanned += 1
        active = [p for p in PROVIDER_PATTERNS if any(n in text for n in p.needles)]
        want_pem = _PEM_NEEDLE in text
        want_auth = _BASIC_AUTH_NEEDLE in text and "@" in text
        lowered_text = text.lower()
        want_generic = not is_doc_path(path) and any(k in lowered_text for k in _GENERIC_KEYWORDS)
        if not (active or want_pem or want_auth or want_generic):
            continue
        lines = text.splitlines()
        for index, line in enumerate(lines):
            line_no = index + 1
            found: list[SecretMatch] = []
            if active or want_pem or want_auth:
                following = lines[index + 1] if index + 1 < len(lines) else None
                found = list(
                    scan_line_provider(
                        path, line_no, line, following, active, pem=want_pem, basic_auth=want_auth
                    )
                )
                provider.extend(found)
            if want_generic and not found:
                generic.extend(scan_line_generic(path, line_no, line))
        if len(provider) > MAX_MATCHES_PER_KIND or len(generic) > MAX_MATCHES_PER_KIND:
            truncated = True
            break
    return TreeScan(tuple(provider), tuple(generic), files_scanned, truncated)


# -------------------------------------------------------------------- history scan


@dataclass(frozen=True)
class HistoryScan:
    """Provider-format credentials that were committed at some point but are gone from HEAD."""

    matches: tuple[SecretMatch, ...]
    lines_scanned: int


_HISTORY_PATTERNS = tuple(p for p in PROVIDER_PATTERNS if p.in_history)


def scan_history(repo: RepoSnapshot, max_commits: int) -> HistoryScan:
    """Scan lines added by the last ``max_commits`` commits for provider-format credentials.

    Anything whose value is still present in the working tree is left to the tree rules.
    Each distinct credential is reported once, at the oldest commit that introduced it
    (``git log`` runs newest first, so later sightings overwrite earlier ones).
    """
    in_tree = scan_tree(repo).anchors
    found: dict[tuple[str, str], SecretMatch] = {}
    lines_scanned = 0
    previous: AddedLine | None = None
    stream = repo.iter_added_lines(max_commits=max_commits, max_line_length=MAX_LINE_LENGTH)
    for added in _with_sentinel(stream):
        if previous is not None and is_scannable_path(previous.path):
            lines_scanned += 1
            adjacent = (
                added is not None
                and added.sha == previous.sha
                and added.path == previous.path
                and added.line == previous.line + 1
            )
            for match in scan_line_provider(
                previous.path,
                previous.line,
                previous.text,
                added.text if adjacent and added is not None else None,
                _HISTORY_PATTERNS,
                basic_auth=False,
            ):
                key = (match.kind, match.anchor)
                if key not in in_tree:
                    found[key] = SecretMatch(
                        kind=match.kind,
                        path=match.path,
                        line=match.line,
                        preview=match.preview,
                        anchor=match.anchor,
                        confidence=match.confidence,
                        sha=previous.sha,
                    )
        previous = added
    ordered = sorted(found.values(), key=lambda m: (m.path, m.line, m.kind, m.sha, m.anchor))
    return HistoryScan(tuple(ordered), lines_scanned)


def _with_sentinel(stream: Iterable[AddedLine]) -> Iterator[AddedLine | None]:
    """The stream plus a trailing ``None`` so the last line is processed with no successor."""
    yield from stream
    yield None
