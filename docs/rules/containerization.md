# Containerization rules (CTR)

Dockerfiles are parsed, never built. Files under node_modules, vendor, third_party and fixture directories are ignored; at most 30 Dockerfiles and 20 compose files are parsed. Content rules are not applicable without a Dockerfile; CTR005 is not applicable when nothing is containerized. Templated images (`FROM ${BASE}`) are never guessed. CTR010 names the variable only and never prints its value.

| Rule | Stage | Severity | Detects | Why it matters | How to fix |
| --- | --- | --- | --- | --- | --- |
| CTR001 | stabilization | medium | Container build definition present | A released product must be buildable and runnable the same way on every machine; a Dockerfile makes the runtime environment reproducible for the first customers. | Add a Dockerfile (or Containerfile) that builds and runs the application. |
| CTR002 | stabilization | low | .dockerignore present | Without a .dockerignore the whole working tree (including .git, local .env files and build output) is sent to the build and can end up inside the shipped image. | Add a .dockerignore excluding .git, .env*, caches and build output. |
| CTR003 | growth | medium | Base images pinned to a version | An untagged or :latest base image changes underneath you; with more developers and customers, two builds of the same commit must produce the same image. | Pin every FROM to a specific tag (e.g. python:3.12-slim) or, better, a digest. |
| CTR004 | growth | medium | Container does not run as root | A process running as root in a container turns any application bug into a much larger compromise; hardening the runtime is expected once real customers depend on it. | Create an unprivileged user and add `USER <name-or-uid>` to the final stage. |
| CTR005 | growth | low | Orchestration manifest present | A growing team needs one command to bring up the product with its dependencies; compose files, Helm charts or Kubernetes manifests capture that as code. | Add a compose.yaml (or Helm chart / Kubernetes manifests) for the services. |
| CTR006 | growth | medium | Compose files avoid dangerous settings | privileged mode, host networking and a mounted Docker socket each give a container control of the host, and untagged images make deployments unrepeatable. | Remove `privileged: true`, `network_mode: host` and /var/run/docker.sock mounts, and pin every `image:` to a version tag. |
| CTR007 | growth | medium | No unverified remote code in image builds | `curl \| sh` and `ADD https://...` execute or embed whatever the remote server returns at build time, with no integrity check: a supply-chain risk that grows with the user base. | Download to a file, verify a checksum or signature, then run it; for ADD use `--checksum=sha256:...` or a pinned package instead. |
| CTR008 | maturity | low | Multi-stage build | Multi-stage builds keep compilers and build-time dependencies out of the shipped image: smaller, faster to deploy and with less attack surface. An optimisation expected of an established product (interpreted-language images may not need it). | Split the Dockerfile into a build stage and a minimal runtime stage. |
| CTR009 | maturity | low | Container health is declared | Orchestrators can only restart or route around a broken container if the image or manifest says how to check it; an established product is operated, not just started. | Add a HEALTHCHECK, a compose `healthcheck:` or Kubernetes probes. |
| CTR010 | inception | high | No secrets baked into images | ENV and ARG values are stored in the image layers and history: anyone who can pull the image can read them. This is dangerous at every stage. | Remove the value, rotate the credential, and inject it at runtime (environment, secret manager) or at build time with `RUN --mount=type=secret`. |

## How to suppress

Disable a rule for the whole repository in `rung.toml`:

```toml
[rules]
disable = ["CTR010"]
```

To accept a single finding instead, add its fingerprint to the baseline file
(`rung baseline --output rung-baseline.json --justification "..."`); every baseline entry
needs a non-empty `justification`. Severity can be changed per rule under `[rules.severity]`.
