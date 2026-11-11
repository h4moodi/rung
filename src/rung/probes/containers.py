"""Containerization probe: is the product reproducibly packaged? (rules CTR001-CTR010)

Static analysis only: Dockerfiles are parsed, never built. Rules about Dockerfile or
compose contents are not applicable when the repo has none.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from rung.collect import RepoSnapshot
from rung.models import Check, Confidence, Dimension, Hit, Location, Severity, Stage
from rung.probes._build_common import is_vendored, load_yaml
from rung.probes._dockerfile import BuildStage, Dockerfile, parse_dockerfile
from rung.registry import rule

#: Caps on files parsed per rule, so monorepos stay fast.
MAX_DOCKERFILES = 30
MAX_COMPOSE_FILES = 20
MAX_MANIFEST_FILES = 100
MAX_HITS = 50

_DOCKERFILE_NAME = re.compile(
    r"^(?:(?:dockerfile|containerfile)(?:\.[\w.-]+)?|[\w.-]+\.dockerfile)$", re.I
)
_NOT_DOCKERFILE_SUFFIXES = (".dockerignore", ".md", ".txt", ".j2", ".tmpl", ".tpl", ".erb")
_COMPOSE_NAME = re.compile(r"^(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$", re.I)
_MANIFEST_DIRS = frozenset(
    {"k8s", "kubernetes", "kube", "manifests", "deploy", "deployment", "deployments", "helm",
     "charts", "kustomize", "templates", "base", "overlays"}
)  # fmt: skip
_K8S_OBJECT = re.compile(r"(?m)^apiVersion:.*(?:\n.*)*?^kind:|^kind:.*(?:\n.*)*?^apiVersion:")
_K8S_PROBE = re.compile(r"^\s*(?:livenessProbe|readinessProbe|startupProbe)\s*:")
_ORCHESTRATION_NAMES = ("Chart.yaml", "skaffold.yaml", "skaffold.yml", "Tiltfile",
                        "kustomization.yaml", "kustomization.yml")  # fmt: skip
_NONROOT_IMAGE = re.compile(r"nonroot|-unprivileged\b|^cgr\.dev/chainguard/", re.I)
_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    r"|\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?(?:<\(|\$\()\s*(?:curl|wget)\b"
)
_SECRET_NAME = re.compile(
    r"PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?", re.I
)
_NOT_SECRET_SUFFIX = re.compile(
    r"_(?:FILE|PATH|DIR|URL|URI|NAME|ENDPOINT|EXPIRY|EXPIRES(?:_IN)?|TTL|LENGTH|ALGORITHM|TYPE"
    r"|HEADER|VERSION|ENABLED|REQUIRED|TIMEOUT|LIFETIME|PREFIX|LOCATION)$",
    re.I,
)
_PLACEHOLDER = re.compile(
    r"^(?:|change[_-]?me|placeholder|example|dummy|todo|none|null|nil|true|false|unset|undefined"
    r"|x{3,}|\*+|<.*>|(?:your|replace|insert|my)[_-].*|[\d.]+|\.{0,2}/.*)$",
    re.I,
)
_ASSIGNMENT = re.compile(r"""([A-Za-z_]\w*)=("(?:[^"\\]|\\.)*"|'[^']*'|\S*)""")


# ----------------------------------------------------------------------- helpers


def _dockerfile_paths(repo: RepoSnapshot) -> list[str]:
    return [
        f
        for f in repo.files
        if _DOCKERFILE_NAME.match(PurePosixPath(f).name)
        and not f.lower().endswith(_NOT_DOCKERFILE_SUFFIXES)
        and not is_vendored(f)
    ]


def _dockerfiles(repo: RepoSnapshot) -> tuple[list[Dockerfile], str]:
    """Parsed Dockerfiles (capped) and a note for the summary when the cap was hit."""
    paths = _dockerfile_paths(repo)
    note = (
        f" (first {MAX_DOCKERFILES} of {len(paths)} Dockerfiles)"
        if len(paths) > MAX_DOCKERFILES
        else ""
    )
    parsed = []
    for path in paths[:MAX_DOCKERFILES]:
        text = repo.read_text(path)
        if text is not None:
            parsed.append(parse_dockerfile(path, text))
    return parsed, note


def _compose_paths(repo: RepoSnapshot) -> list[str]:
    found = [
        f for f in repo.files if _COMPOSE_NAME.match(PurePosixPath(f).name) and not is_vendored(f)
    ]
    return found[:MAX_COMPOSE_FILES]


def _manifest_paths(repo: RepoSnapshot) -> list[str]:
    """YAML files in conventional deployment directories that hold Kubernetes objects."""
    out: list[str] = []
    candidates = [
        f
        for f in repo.files
        if f.lower().endswith((".yaml", ".yml"))
        and not is_vendored(f)
        and {p.lower() for p in PurePosixPath(f).parts[:-1]} & _MANIFEST_DIRS
    ]
    for path in candidates[:MAX_MANIFEST_FILES]:
        if _K8S_OBJECT.search(repo.read_text(path) or ""):
            out.append(path)
    return out


def _image_problem(image: str) -> str | None:
    """Why an image reference is unpinned, or None when it is pinned or cannot be judged."""
    if not image or "$" in image or "@sha256:" in image:
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "has no tag (defaults to :latest)"
    if last.rsplit(":", 1)[1].lower() == "latest":
        return "uses the mutable :latest tag"
    return None


def _earlier_stage(df: Dockerfile, stage: BuildStage) -> BuildStage | None:
    """The earlier build stage this stage is based on, if its FROM names one."""
    ref = stage.image.lower()
    for prior in df.stages[: stage.index]:
        if ref in {prior.name, str(prior.index)}:
            return prior
    return None


def _capped(hits: list[Hit]) -> tuple[list[Hit], str]:
    if len(hits) <= MAX_HITS:
        return hits, ""
    return hits[:MAX_HITS], f" (showing the first {MAX_HITS})"


def _result(hits: list[Hit], ok: str, bad: str, evidence: list[str]) -> Check:
    if not hits:
        return Check.ok(ok, evidence=evidence[:3])
    count = len(hits)
    hits, note = _capped(hits)
    return Check.fail(f"{count} {bad}{note}", hits=hits)


_NO_DOCKERFILE = "No Dockerfile or Containerfile in the repository"

# ------------------------------------------------------------------------- rules


@rule(
    id="CTR001",
    title="Container build definition present",
    dimension=Dimension.containers,
    stage=Stage.stabilization,
    severity=Severity.medium,
    description=(
        "A released product must be buildable and runnable the same way on every machine; a "
        "Dockerfile makes the runtime environment reproducible for the first customers."
    ),
    remediation="Add a Dockerfile (or Containerfile) that builds and runs the application.",
    weight=2.0,
)
def dockerfile_present(repo: RepoSnapshot) -> Check:
    paths = _dockerfile_paths(repo)
    if not paths:
        return Check.fail(_NO_DOCKERFILE, at="Dockerfile")
    return Check.ok(
        f"{len(paths)} container build file(s) found, e.g. {paths[0]}", evidence=paths[:3]
    )


@rule(
    id="CTR002",
    title=".dockerignore present",
    dimension=Dimension.containers,
    stage=Stage.stabilization,
    severity=Severity.low,
    description=(
        "Without a .dockerignore the whole working tree (including .git, local .env files and "
        "build output) is sent to the build and can end up inside the shipped image."
    ),
    remediation="Add a .dockerignore excluding .git, .env*, caches and build output.",
)
def dockerignore_present(repo: RepoSnapshot) -> Check:
    paths = _dockerfile_paths(repo)
    if not paths:
        return Check.na(_NO_DOCKERFILE)
    if repo.exists(".dockerignore"):
        return Check.ok(".dockerignore found at the repository root", evidence=[".dockerignore"])
    missing: list[str] = []
    for path in paths:
        parent = PurePosixPath(path).parent
        expected = (parent / ".dockerignore").as_posix()
        if not (repo.exists(expected) or repo.exists(f"{path}.dockerignore")):
            missing.append(expected)
    missing = sorted(set(missing))
    if not missing:
        return Check.ok(
            f"Every one of the {len(paths)} Dockerfile(s) has a .dockerignore beside it"
        )
    hits = [Hit(m, "No .dockerignore for this build context") for m in missing]
    return _result(hits, "", "build context(s) without a .dockerignore", [])


@rule(
    id="CTR003",
    title="Base images pinned to a version",
    dimension=Dimension.containers,
    stage=Stage.growth,
    severity=Severity.medium,
    description=(
        "An untagged or :latest base image changes underneath you; with more developers and "
        "customers, two builds of the same commit must produce the same image."
    ),
    remediation="Pin every FROM to a specific tag (e.g. python:3.12-slim) or, better, a digest.",
)
def base_images_pinned(repo: RepoSnapshot) -> Check:
    dockerfiles, note = _dockerfiles(repo)
    if not dockerfiles:
        return Check.na(_NO_DOCKERFILE)
    hits: list[Hit] = []
    total = 0
    for df in dockerfiles:
        for stage in df.stages:
            if stage.image.lower() == "scratch" or _earlier_stage(df, stage):
                continue
            total += 1
            problem = _image_problem(stage.image)
            if problem:
                hits.append(Hit(df.path, f"Base image `{stage.image}` {problem}", stage.line))
    return _result(
        hits,
        f"All {total} external base image reference(s) in {len(dockerfiles)} Dockerfile(s) are "
        f"pinned or templated{note}",
        f"unpinned base image(s) out of {total}",
        [d.path for d in dockerfiles],
    )


@rule(
    id="CTR004",
    title="Container does not run as root",
    dimension=Dimension.containers,
    stage=Stage.growth,
    severity=Severity.medium,
    confidence=Confidence.medium,
    description=(
        "A process running as root in a container turns any application bug into a much larger "
        "compromise; hardening the runtime is expected once real customers depend on it."
    ),
    remediation="Create an unprivileged user and add `USER <name-or-uid>` to the final stage.",
)
def non_root_user(repo: RepoSnapshot) -> Check:
    dockerfiles, note = _dockerfiles(repo)
    if not dockerfiles:
        return Check.na(_NO_DOCKERFILE)
    hits: list[Hit] = []
    judged = 0
    for df in dockerfiles:
        stage: BuildStage | None = df.stages[-1] if df.stages else None
        user = None
        final = stage
        while stage is not None:  # follow `FROM earlier-stage` chains
            final = stage
            user = stage.last("USER")
            if user:
                break
            stage = _earlier_stage(df, stage)
        if final is None:
            continue
        if user is None:
            if "$" in final.image or _NONROOT_IMAGE.search(final.image):
                continue  # templated: cannot judge; known non-root base image: fine
            judged += 1
            hits.append(
                Hit(
                    df.path,
                    "Final stage has no USER instruction, so it runs as root",
                    df.stages[-1].line,
                )
            )
            continue
        judged += 1
        name = user.args.split(":")[0].strip()
        if name.lower() in {"root", "0"}:
            hits.append(Hit(df.path, f"Final stage switches to `USER {name}`", user.line))
    return _result(
        hits,
        f"{judged} Dockerfile(s) judged, none runs its final stage as root{note}",
        f"of {judged} Dockerfile(s) run as root",
        [d.path for d in dockerfiles],
    )


@rule(
    id="CTR005",
    title="Orchestration manifest present",
    dimension=Dimension.containers,
    stage=Stage.growth,
    severity=Severity.low,
    description=(
        "A growing team needs one command to bring up the product with its dependencies; "
        "compose files, Helm charts or Kubernetes manifests capture that as code."
    ),
    remediation="Add a compose.yaml (or Helm chart / Kubernetes manifests) for the services.",
)
def orchestration_present(repo: RepoSnapshot) -> Check:
    found = _compose_paths(repo) + [
        f for f in repo.find_named(*_ORCHESTRATION_NAMES) if not is_vendored(f)
    ]
    found = found or _manifest_paths(repo)
    if found:
        return Check.ok(
            f"{len(found)} orchestration file(s) found, e.g. {found[0]}", evidence=found[:3]
        )
    if not _dockerfile_paths(repo):
        return Check.na("Nothing is containerized yet (reported by CTR001)")
    return Check.fail(
        "No compose file, Helm chart, Kubernetes manifest, skaffold or Tilt config found",
        at="compose.yaml",
    )


@rule(
    id="CTR006",
    title="Compose files avoid dangerous settings",
    dimension=Dimension.containers,
    stage=Stage.growth,
    severity=Severity.medium,
    description=(
        "privileged mode, host networking and a mounted Docker socket each give a container "
        "control of the host, and untagged images make deployments unrepeatable."
    ),
    remediation=(
        "Remove `privileged: true`, `network_mode: host` and /var/run/docker.sock mounts, "
        "and pin every `image:` to a version tag."
    ),
    tags=("security",),
)
def compose_safe(repo: RepoSnapshot) -> Check:
    paths = _compose_paths(repo)
    if not paths:
        return Check.na("No compose files")
    hits: list[Hit] = []
    parsed = 0
    image_line = re.compile(r"^\s*image:\s*['\"]?([^'\"\s#]+)")
    for path in paths:
        text = repo.read_text(path)
        doc = load_yaml(text)
        services = doc.get("services") if isinstance(doc, dict) else None
        if text is None or not isinstance(services, dict):
            continue
        parsed += 1
        # an `image:` beside `build:` only names the locally built result
        pulled = {
            str(s["image"]) for s in services.values()
            if isinstance(s, dict) and "image" in s and "build" not in s
        }  # fmt: skip
        for no, line in enumerate(text.splitlines(), start=1):
            code = line.split(" #", 1)[0]
            if code.lstrip().startswith("#"):
                continue
            if re.match(r"^\s*privileged:\s*['\"]?(?:true|yes|on)\b", code, re.I):
                hits.append(Hit(path, "Service runs in privileged mode", no))
            elif re.match(r"^\s*network_mode:\s*['\"]?host\b", code):
                hits.append(Hit(path, "Service uses the host network namespace", no))
            elif "/var/run/docker.sock" in code:
                hits.append(Hit(path, "Docker socket is mounted into a service", no))
            else:
                m = image_line.match(code)
                problem = _image_problem(m.group(1)) if m and m.group(1) in pulled else None
                if m and problem:
                    hits.append(Hit(path, f"Image `{m.group(1)}` {problem}", no))
    if not parsed:
        return Check.na(f"None of the {len(paths)} compose file(s) could be parsed")
    return _result(
        hits,
        f"{parsed} compose file(s) checked, no dangerous settings (cap {MAX_COMPOSE_FILES})",
        f"dangerous compose setting(s) in {parsed} file(s)",
        paths,
    )


@rule(
    id="CTR007",
    title="No unverified remote code in image builds",
    dimension=Dimension.containers,
    stage=Stage.growth,
    severity=Severity.medium,
    description=(
        "`curl | sh` and `ADD https://...` execute or embed whatever the remote server returns "
        "at build time, with no integrity check: a supply-chain risk that grows with the user base."
    ),
    remediation=(
        "Download to a file, verify a checksum or signature, then run it; for ADD use "
        "`--checksum=sha256:...` or a pinned package instead."
    ),
    tags=("security",),
)
def no_remote_code(repo: RepoSnapshot) -> Check:
    dockerfiles, note = _dockerfiles(repo)
    if not dockerfiles:
        return Check.na(_NO_DOCKERFILE)
    hits: list[Hit] = []
    for df in dockerfiles:
        for ins in df.instructions:
            if ins.keyword == "RUN" and _PIPE_TO_SHELL.search(ins.args):
                hits.append(
                    Hit(
                        df.path,
                        "RUN pipes a download straight into a shell",
                        ins.line,
                        ins.end_line,
                    )
                )
            elif ins.keyword == "ADD" and "--checksum=" not in ins.args:
                if any(
                    t.lower().startswith(("http://", "https://")) for t in ins.args.split()[:-1]
                ):
                    hits.append(
                        Hit(
                            df.path,
                            "ADD fetches a remote URL without a checksum",
                            ins.line,
                            ins.end_line,
                        )
                    )
    return _result(
        hits,
        f"No pipe-to-shell or unverified remote ADD in {len(dockerfiles)} Dockerfile(s){note}",
        "unverified remote download(s) in image builds",
        [d.path for d in dockerfiles],
    )


@rule(
    id="CTR008",
    title="Multi-stage build",
    dimension=Dimension.containers,
    stage=Stage.maturity,
    severity=Severity.low,
    confidence=Confidence.medium,
    description=(
        "Multi-stage builds keep compilers and build-time dependencies out of the shipped "
        "image: smaller, faster to deploy and with less attack surface. An optimisation "
        "expected of an established product (interpreted-language images may not need it)."
    ),
    remediation="Split the Dockerfile into a build stage and a minimal runtime stage.",
)
def multi_stage(repo: RepoSnapshot) -> Check:
    dockerfiles, note = _dockerfiles(repo)
    if not dockerfiles:
        return Check.na(_NO_DOCKERFILE)
    best = max(dockerfiles, key=lambda d: (len(d.stages), d.path))
    if len(best.stages) >= 2:
        return Check.ok(
            f"{best.path} has {len(best.stages)} build stages{note}", evidence=[best.path]
        )
    first = dockerfiles[0]
    return Check.fail(
        f"None of the {len(dockerfiles)} Dockerfile(s) uses more than one build stage{note}",
        at=first.path,
        line=first.stages[0].line if first.stages else None,
    )


@rule(
    id="CTR009",
    title="Container health is declared",
    dimension=Dimension.containers,
    stage=Stage.maturity,
    severity=Severity.low,
    description=(
        "Orchestrators can only restart or route around a broken container if the image or "
        "manifest says how to check it; an established product is operated, not just started."
    ),
    remediation="Add a HEALTHCHECK, a compose `healthcheck:` or Kubernetes probes.",
)
def health_declared(repo: RepoSnapshot) -> Check:
    dockerfiles, note = _dockerfiles(repo)
    for df in dockerfiles:
        for ins in df.instructions:
            if ins.keyword == "HEALTHCHECK" and ins.args.strip().upper() != "NONE":
                return Check.ok(
                    f"HEALTHCHECK declared at {df.path}:{ins.line}",
                    evidence=[Location(path=df.path, start_line=ins.line)],
                )
    compose = _compose_paths(repo)
    manifests = _manifest_paths(repo)
    for path, pattern in [(p, re.compile(r"^\s*healthcheck\s*:")) for p in compose] + [
        (p, _K8S_PROBE) for p in manifests
    ]:
        for no, line in enumerate(repo.read_lines(path), start=1):
            if pattern.match(line):
                return Check.ok(
                    f"Health check declared at {path}:{no}",
                    evidence=[Location(path=path, start_line=no)],
                )
    targets = [d.path for d in dockerfiles] + compose + manifests
    if not targets:
        return Check.na("No Dockerfile, compose file or Kubernetes manifest")
    return Check.fail(
        f"No health check declared in {len(targets)} container file(s){note}",
        at=targets[0],
    )


@rule(
    id="CTR010",
    title="No secrets baked into images",
    dimension=Dimension.containers,
    stage=Stage.inception,
    severity=Severity.high,
    confidence=Confidence.medium,
    description=(
        "ENV and ARG values are stored in the image layers and history: anyone who can pull "
        "the image can read them. This is dangerous at every stage."
    ),
    remediation=(
        "Remove the value, rotate the credential, and inject it at runtime (environment, "
        "secret manager) or at build time with `RUN --mount=type=secret`."
    ),
    weight=2.0,
    tags=("security", "secrets"),
)
def no_baked_secrets(repo: RepoSnapshot) -> Check:
    dockerfiles, note = _dockerfiles(repo)
    if not dockerfiles:
        return Check.na(_NO_DOCKERFILE)
    hits: list[Hit] = []
    for df in dockerfiles:
        for ins in df.instructions:
            if ins.keyword not in {"ENV", "ARG"}:
                continue
            pairs = _ASSIGNMENT.findall(ins.args)
            if not pairs and ins.keyword == "ENV":  # legacy `ENV NAME value`
                name, _, value = ins.args.partition(" ")
                pairs = [(name, value)]
            for name, raw in pairs:
                value = raw.strip().strip("\"'")
                if not _SECRET_NAME.search(name) or _NOT_SECRET_SUFFIX.search(name):
                    continue
                if "$" in value or _PLACEHOLDER.match(value):
                    continue
                # the value itself is deliberately never put in the message
                hits.append(
                    Hit(
                        df.path,
                        f"{ins.keyword} {name} has a hard-coded value baked into the image",
                        ins.line,
                    )
                )
    return _result(
        hits,
        f"No hard-coded secret-looking ENV/ARG values in {len(dockerfiles)} Dockerfile(s){note}",
        "secret-looking ENV/ARG value(s) baked into images",
        [d.path for d in dockerfiles],
    )
