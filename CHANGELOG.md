# Changelog

All notable changes to rung are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-10

### Added

- Six audit probes: commit history, containerization, testing, CI/CD, documentation, security.
- Stage classification on the Klotins et al. progression model (inception, stabilization,
  growth, maturity) with stage-aware severity and a prioritized improvement checklist.
- CLI (`rung audit / rules / stages / baseline / serve`) with terminal, JSON and SARIF 2.1.0
  output and CI-friendly exit codes.
- FastAPI backend with audit history and safe remote cloning.
- Next.js + Tailwind dashboard with the stage ladder, dimension scores, checklist and
  findings explorer.
- `rung.toml` configuration: rule toggles, severity overrides, path ignores, justified baselines.
- Benchmark harness for the diagnostic-accuracy study (`scripts/benchmark.py`).
