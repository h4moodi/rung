# Security rules (`SEC0xx`)

Dimension: `security`. Every rule is a pure, offline function of the repository snapshot.
**No network, ever:** looking dependencies up in a vulnerability database (CVE/OSV) is out of
scope, because the same commit would then produce different reports on different days.
Use a dedicated scanner in CI for that; SEC013 checks that one is wired in.

**Secret values are never printed.** Findings name the credential *type* and location and
show at most a redacted preview (public format prefix, masked body, length).

Suppressing any rule: disable it (`[rules] disable = ["SEC0xx"]` in `rung.toml`), exclude
paths (`[paths] ignore = ["vendor/**"]`), or add a baseline entry with a non-empty
`justification`. Prefer the narrowest option.

Shared noise controls for the secret rules: binary files, lockfiles, minified files, source
maps, files over 1 MB and lines over 2000 characters are skipped. Placeholders are ignored
(values containing example / sample / dummy / placeholder / changeme / your_ / xxxx, angle
bracket or template markers, single-character fillers, the AWS documentation keys). Paths that
look like tests, fixtures, docs or examples are still reported, one confidence level lower.

| ID | Stage | Severity | Confidence | Checks |
| --- | --- | --- | --- | --- |
| SEC001 | inception | critical | high | Provider-format credentials in the working tree |
| SEC002 | inception | medium | low | Generic hard-coded secret assignments |
| SEC003 | inception | critical | high | Private key / keystore files |
| SEC004 | inception | high | high | Populated `.env` files |
| SEC005 | inception | high | medium | Credentials removed from HEAD but present in history |
| SEC006 | inception | low | medium | `.gitignore` covers `.env` |
| SEC007 | inception | medium | medium | A dependency manifest exists |
| SEC008 | stabilization | medium | medium | Lockfile per manifest |
| SEC009 | growth | low | medium | Unpinned / wildcard versions |
| SEC011 | growth | low | medium | Dependency update automation |
| SEC012 | maturity | low | high | Security policy |
| SEC013 | maturity | medium | medium | Security scanning in CI / pre-commit |
| SEC014 | stabilization | low | medium | Large binary blobs |

(SEC010, typosquat detection, is reserved and not implemented yet.)

## SEC001: No provider credentials in the working tree
- **Detects:** tokens with a distinctive provider format: AWS access key IDs, GitHub tokens
  (classic and fine-grained), GitLab personal access tokens, Slack tokens and webhook URLs,
  Stripe live keys, Google API keys, SendGrid, npm and PyPI tokens, Anthropic/OpenAI keys
  (high confidence); generic `sk-` keys and Twilio API keys (medium); JWT-shaped strings
  (low confidence, medium severity); PEM private-key blocks inside text files (only when key
  material follows the header); URLs with an embedded user and password (high severity,
  medium confidence; default passwords or local hosts are low/low). At most 200 hits.
- **Why (inception):** a committed credential is compromised at any stage, so this is never
  down-ranked.
- **Fix:** rotate the credential **first**, then remove it from the code, load it from the
  environment or a secret manager, then purge it from history (`git filter-repo` / BFG).
- **Suppress:** baseline the finding with a justification (e.g. a revoked key kept as a fixture).

## SEC002: No generic hard-coded secrets
- **Detects:** a quoted literal of 8+ characters with entropy >= 3.0 bits/char assigned to a
  name ending in password, secret, api_key, access_key, private_key, client_secret, token,
  auth, pwd or credential. Env/template references, file paths, identifier-like values and
  documentation files are excluded. Lines already reported by SEC001 are not repeated.
- **Why (inception):** literals cannot be rotated without a code change and leak via every clone.
- **Fix:** read the value from the environment or a secret manager; rotate it if it was real.
- **Suppress:** heuristic and low confidence by design; baseline false positives or ignore paths.

## SEC003: No private keys or keystores committed
- **Detects:** `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `*.pem`, `*.key`, `*.ppk` whose
  content has a private-key header (public certificates and `.pub` files pass); non-empty
  `*.p12`, `*.pfx`, `*.jks`, `*.keystore` (medium confidence; Android `debug.keystore` low).
- **Why (inception):** the key holder can impersonate the server, user or signing identity.
- **Fix:** revoke and regenerate the key pair, delete the file, ignore the pattern, purge history.
- **Suppress:** baseline with a justification (e.g. a throwaway test CA).

## SEC004: No environment files committed
- **Detects:** `.env` and `.env.<name>` with at least one real `KEY=value` (empty,
  placeholder and `${VAR}` values do not count). Template names (example, sample, template,
  dist, defaults, ...) are ignored. Reports the path and the number of values, never a value.
- **Why (inception):** `.env` is where database passwords and API keys live.
- **Fix:** rotate real values, `git rm --cached` the file, ignore it, commit `.env.example`.
- **Suppress:** baseline files that hold only non-secret defaults.

## SEC005: No credentials left in git history
- **Detects:** SEC001 provider formats and PEM blocks (not JWTs or URLs) in lines added by the
  newest 500 commits whose value is no longer in the working tree. Each credential is
  reported once, with the path and short SHA of the oldest commit that added it. The summary
  says when the scan was capped or the clone is shallow. Not applicable without git.
- **Why (inception):** deleting a secret in a later commit does not unpublish it.
- **Fix:** rotate first; rewrite history and force-push only if the value must disappear.
- **Suppress:** baseline with a justification stating the credential was rotated.

## SEC006: .gitignore covers environment files
- **Detects:** a root `.gitignore` with no pattern matching `.env`, in a repo that shows env
  usage (a `.env*` file, a dotenv-style dependency, or `env_file` in a compose file).
  Not applicable without a `.gitignore` (the docs probe owns that) or without env usage.
- **Why (inception):** the first `git add .` otherwise commits local credentials.
- **Fix:** add `.env` and `.env.*` (with `!.env.example`) to `.gitignore`.

## SEC007: Dependencies declared in a manifest
- **Detects:** source code in a language with a standard manifest, but no manifest
  (requirements*.txt, pyproject.toml, Pipfile, setup.py/cfg, package.json, go.mod, Cargo.toml,
  pom.xml, build.gradle(.kts), Gemfile, composer.json, *.csproj, mix.exs, ...).
- **Why (inception):** without one the project cannot be installed or audited reproducibly.
- **Fix:** declare dependencies in the ecosystem's manifest.

## SEC008: Lockfile committed for each dependency manifest
- **Detects:** package.json with dependencies, poetry/pdm/uv pyproject.toml, Pipfile,
  Cargo.toml, go.mod with requires, Gemfile, composer.json without their lockfile in the same
  or an ancestor directory (workspace roots). A `requirements.txt` whose entries are all
  `==`-pinned counts as locked. Rust libraries and example/test paths get low confidence.
- **Why (stabilization):** a released product must ship the dependency tree that was tested.
- **Fix:** generate the lockfile and commit it.

## SEC009: No unpinned or wildcard dependency versions
- **Detects:** requirements*.txt entries with no version specifier (options, URLs, editable
  and local installs are skipped) and package.json dependencies set to `*`, `latest`, `x` or
  empty. Ranges such as `^1.2.3` or `>=1,<2` are fine.
- **Why (growth):** unconstrained versions change builds without a commit.
- **Fix:** add a version constraint to each dependency.

## SEC011: Dependency update automation configured
- **Detects:** no Dependabot, Renovate or pyup configuration in a repo that has a manifest.
  Bots configured only in a hosting web UI are invisible to rung.
- **Why (growth):** manual upgrades stop scaling with the team and the dependency tree.
- **Fix:** add `.github/dependabot.yml` or a Renovate config.

## SEC012: Security policy present
- **Detects:** no non-empty `SECURITY.*` in the root, `docs/` or `.github/`.
- **Why (maturity):** an established product needs a private vulnerability-reporting channel.
- **Fix:** add `SECURITY.md` with supported versions and a reporting contact.

## SEC013: Automated security scanning in CI or pre-commit
- **Detects:** no known scanner (CodeQL, gitleaks, trufflehog, detect-secrets, semgrep, bandit,
  trivy, grype, snyk, osv-scanner, npm/yarn/pnpm audit, pip-audit, cargo audit/deny, gosec,
  govulncheck, dependency-review-action, scorecard, ...) in CI or pre-commit files; comment
  lines are ignored. Scanning enabled only in platform settings is invisible, hence medium
  confidence.
- **Why (maturity):** review alone does not catch vulnerable dependencies or leaked secrets.
- **Fix:** add a scanner job or pre-commit hook.

## SEC014: No large binary blobs tracked
- **Detects:** tracked binary files over 5 MB that are not images, fonts, PDFs, audio or video.
- **Why (stabilization):** they bloat every clone forever and are usually build artifacts.
- **Fix:** remove and ignore the artifact; publish via releases, a registry or Git LFS.
