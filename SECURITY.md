# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/h4moodi/rung/security/advisories/new)
rather than a public issue. Include the rung version, a minimal reproduction and the
impact you expect. You should get an acknowledgement within 7 days.

## Scope and threat model

rung reads repositories that may be hostile. The guarantees it aims to keep:

- **Read-only.** rung never writes inside an audited repository and never executes code
  from it (no builds, no tests, no hooks, no `docker` invocations).
- **No path escape.** Files are only read if they resolve inside the repository root;
  symlinks pointing elsewhere are ignored.
- **No secret disclosure.** Detected credentials are reported by type and location with a
  redacted preview; the value is never written to output, logs or stored reports.
- **No network during analysis.** The only network access is the optional clone performed
  by the API for `https://` URLs on an allowlisted host.

The HTTP API has no authentication in v1. It clones and reads repositories on behalf of the
caller, so run it on localhost or a trusted network only. See `docs/api.md`.

## Out of scope

rung detects and reports. It does not exploit findings, and it must only be pointed at
repositories you own or are authorized to assess.
