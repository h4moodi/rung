# CI/CD rules (CIC)

All providers (GitHub Actions, GitLab CI, CircleCI, Jenkins, Azure Pipelines, Bitbucket, Travis, Drone, Woodpecker, Buildkite) count for CIC001 and CIC003-CIC005. CIC002 and CIC006-CIC009 analyse GitHub Actions only and are not applicable without workflows. With no CI at all, CIC003-CIC005 fail (the practice is absent) while CIC002 is not applicable. CIC006 accepts first-party `actions/*` and `github/*` on a version tag; a first-party branch ref is a low-severity hit. At most 60 CI files are read.

| Rule | Stage | Severity | Detects | Why it matters | How to fix |
| --- | --- | --- | --- | --- | --- |
| CIC001 | stabilization | medium | CI pipeline defined | Once a product is released, every change must be built and checked the same way; a CI pipeline is what makes the product dependable for its first customers. | Add a pipeline, e.g. .github/workflows/ci.yml, that installs the project and runs its checks on every push and pull request. |
| CIC002 | stabilization | medium | CI runs automatically on push or pull request | A pipeline that only runs when someone remembers to click a button (or on a timer) does not protect the released product from a breaking change. | Trigger the main workflow with `on: [push, pull_request]` (optionally filtered to your default branch) instead of only workflow_dispatch or schedule. |
| CIC003 | stabilization | medium | CI runs the tests | Tests only stabilise a product if they run on every change; a pipeline that merely builds lets regressions reach the first customers. | Add a CI step that runs the test suite (e.g. `pytest`, `npm test`, `go test ./...`) and fails the build when a test fails. |
| CIC004 | growth | low | CI runs lint or static analysis | As the team grows, style and correctness rules have to be enforced by the pipeline rather than by reviewers' memory, or review time and defect rates scale with headcount. | Add a lint/static-analysis step to CI (e.g. `ruff check`, `eslint .`, `golangci-lint run`, `cargo clippy`, or `pre-commit run --all-files`). |
| CIC005 | growth | medium | Delivery is automated | A growing customer base needs frequent, repeatable releases; building and shipping by hand from a laptop does not scale and is a single point of failure. | Add a workflow that builds and publishes or deploys the product (container image, package or release) from CI, triggered by a tag, a release or a merge to main. |
| CIC006 | maturity | medium | Third-party actions pinned to a commit SHA | A tag or branch on someone else's action can be moved to malicious code at any time (as in the tj-actions/changed-files compromise); an established product governs its supply chain by pinning to immutable commits. | Replace `uses: owner/action@v1` with the full 40-character commit SHA and keep the version in a trailing comment; let Dependabot or Renovate update the pins. |
| CIC007 | maturity | medium | Workflow token permissions are least-privilege | Without a `permissions:` block GITHUB_TOKEN may get the repository's broad default scopes, so one compromised step can push code or publish releases. Governing an established product means every workflow declares the access it needs. | Add `permissions: contents: read` at the top of each workflow and grant extra scopes per job only where needed; never use `permissions: write-all`. |
| CIC008 | stabilization | high | No script injection in workflow run steps | `${{ }}` is expanded before the shell runs, so an attacker-controlled value such as a pull-request title becomes part of the script and can run arbitrary commands with the workflow's secrets. As soon as CI exists it must not be remotely exploitable. | Pass the value through an environment variable (`env: TITLE: ${{ github.event.pull_request.title }}`) and reference it as "$TITLE" in the script. |
| CIC009 | stabilization | high | pull_request_target does not check out untrusted code | `pull_request_target` runs with the base repository's secrets and a write token. Checking out the pull request's head there executes a fork's code with those privileges (a 'pwn request'). | Use the `pull_request` trigger for anything that builds or tests PR code. Keep `pull_request_target` for labelling/commenting only and never check out the PR head in it. |

## How to suppress

Disable a rule for the whole repository in `rung.toml`:

```toml
[rules]
disable = ["CIC009"]
```

To accept a single finding instead, add its fingerprint to the baseline file
(`rung baseline --output rung-baseline.json --justification "..."`); every baseline entry
needs a non-empty `justification`. Severity can be changed per rule under `[rules.severity]`.
