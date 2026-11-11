# Documentation rules (`DOC0xx`)

Source: `src/rung/probes/docs.py`. Files are matched by name, case-insensitively, with
any of the extensions (none), `.md`, `.markdown`, `.mdx`, `.rst`, `.txt`, `.adoc`,
`.asciidoc`, `.org`. Only the README and root package manifests are opened. A failing
finding points at the path where the document is expected. `SECURITY.md` is covered by
the security rules.

**Suppressing any rule:** add its id to `rung.toml`:

```toml
[rules]
disable = ["DOC011"]
```

or accept a single finding with a justified entry in the baseline file
(`rung baseline --output rung-baseline.json --justification "..."`).

| ID | Stage | Sev. | Detects (fails when) | Why it matters at this stage | Fix |
| --- | --- | --- | --- | --- | --- |
| DOC001 | inception | medium | No README in the root (or `docs/`, `.github/`, where forges also render it) | The entry point for anyone outside the founding team | Add `README.md` |
| DOC002 | inception | low | No `.gitignore` in the root (per-project ones one level down, e.g. `api/.gitignore`, also pass) | Build output and local secrets get committed from day one | Add a `.gitignore` for the stack |
| DOC003 | stabilization | medium (conf. medium) | README has < 150 words (URLs, badges and HTML tags not counted) or neither a setup/usage-style heading nor a code block; n/a without a README | First customers must be able to install and run the product from the README | Add Installation / Usage sections with commands |
| DOC004 | stabilization | medium | No `LICENSE`/`LICENCE`/`COPYING`/`UNLICENSE` (any suffix) in the root and no `LICENSES/` directory. A `license` declared in `package.json`, `pyproject.toml` or `Cargo.toml` passes, with a summary asking for the file | A released product without terms cannot legally be used or adopted | Add a `LICENSE` file |
| DOC005 | growth | low | No `CONTRIBUTING` in root, `docs/`, `.github/`, `.gitlab/` and no "Contributing" heading in the README | Onboarding by word of mouth stops scaling | Add `CONTRIBUTING.md` |
| DOC006 | growth | low | No `CHANGELOG`/`CHANGES`/`HISTORY`/`RELEASES`/`RELEASE_NOTES`/`NEWS` (root, `docs/`, `doc/`) and no fragment directory (`.changeset/`, `changelog.d/`, `newsfragments/`...) | Customers need to know what changed between versions | Keep a `CHANGELOG.md` |
| DOC007 | growth | low | No `ROADMAP`, no docs-site config (MkDocs, Docusaurus, Sphinx `conf.py`, Read the Docs, mdBook, Antora) and fewer than 2 prose files under `docs/` or `doc/` | Shared knowledge must not live only in people's heads | Add `docs/` or a roadmap |
| DOC008 | growth | medium | No `CODEOWNERS` in root, `docs/`, `.github/`, `.gitlab/` | Reviews need automatic routing; nothing should be orphaned | Add `.github/CODEOWNERS` |
| DOC009 | growth | low | No issue / PR / merge-request templates (`.github/ISSUE_TEMPLATE*`, `PULL_REQUEST_TEMPLATE*`, `.gitlab/*_templates/`) | Incoming reports must be complete once outsiders file them | Add templates |
| DOC010 | maturity | medium | No `ARCHITECTURE`/`DESIGN` doc, `docs/architecture*`, or ADR directory (`docs/adr/`, `docs/decisions/`, `doc/arch/`, `adr/`) | The product outlives its authors; decisions must be recorded | Add `docs/architecture.md` and ADRs |
| DOC011 | maturity | low | No `CODE_OF_CONDUCT` in root, `docs/`, `.github/`, `.gitlab/` | A mature community states expected behaviour | Add `CODE_OF_CONDUCT.md` |

Confidence is high unless noted. The rules deliberately accept alternative spellings and
locations: a missed gap is preferred over a false finding.
