# rung HTTP API

`rung.api.app:create_app` is a FastAPI factory (needs the `api` extra):

```
uvicorn --factory rung.api.app:create_app --host 127.0.0.1 --port 8000
```

## Security model (read this first)

**There is no authentication in v1. Bind the API to localhost or a trusted network only.**
Anyone who can reach it can make the server clone repositories and read directories under
`RUNG_LOCAL_ROOT`, and can read or delete the audit history. The `source` field is treated
as attacker-controlled:

- Remote sources must match `https://<allowlisted host>/<owner>/<repo>[.git]` exactly.
  Other schemes (`ssh`, `git`, `file`, `http`, `ext::`), scp-style addresses, embedded
  credentials, ports, query strings, fragments, extra path segments (GitLab subgroups are
  not supported in v1) and anything starting with `-` are rejected before git runs.
- The URL is rebuilt from the validated parts and passed after `--`. git runs with
  `protocol.ext.allow=never`, `protocol.file.allow=never`, `core.hooksPath=/dev/null`,
  `credential.helper=` (the server's stored credentials are never used, so only public
  repositories can be audited), `http.followRedirects=false` (a renamed repository must be
  given by its current URL), no submodules, `GIT_TERMINAL_PROMPT=0` and a timeout.
- Clones go to a fresh temporary directory that is always deleted. The size limit is
  checked after the clone, so disk use can exceed it briefly, bounded by the timeout.
- Local paths work only when `RUNG_LOCAL_ROOT` is set and only if the path, after
  resolving symlinks, is inside it. Stored and displayed as the path relative to the root.
- Errors never echo the submitted source, git output or server paths.
- CORS allows only `RUNG_CORS_ORIGINS` and `GET`/`POST`/`DELETE`. Do not set it to `*`.
- The audited repository's own `rung.toml` is honoured, exactly as in the CLI.

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `RUNG_DB` | `./rung.sqlite3` | SQLite history file |
| `RUNG_CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `RUNG_ALLOWED_HOSTS` | `github.com,gitlab.com,bitbucket.org,codeberg.org` | Hosts that may be cloned from |
| `RUNG_LOCAL_ROOT` | unset (local paths disabled) | Directory under which local paths may be audited |
| `RUNG_CLONE_TIMEOUT` | `120` | Seconds before a clone is aborted |
| `RUNG_MAX_REPO_MB` | `500` | Maximum size of a cloned repository |

## Endpoints

| Method | Path | Success | Body |
| --- | --- | --- | --- |
| GET | `/api/health` | 200 | `{"status": "ok", "version": "0.1.0"}` |
| GET | `/api/rules` | 200 | `{"items": [{id, title, dimension, stage, severity, confidence, weight, description, remediation}]}` |
| GET | `/api/stages` | 200 | `{"items": [{stage, title, summary, expectations}]}` |
| POST | `/api/audits` | 201 | `{id, source, created_at, report}` |
| GET | `/api/audits?limit=20&offset=0` | 200 | `{"items": [{id, source, created_at, stage, overall_score, counts_by_severity}]}`, newest first; `limit` 1..100 |
| GET | `/api/audits/{id}` | 200 | `{id, source, created_at, report}` |
| GET | `/api/audits/{id}/sarif` | 200 | SARIF 2.1.0 document |
| DELETE | `/api/audits/{id}` | 204 | empty |

`report` is the `AuditReport` JSON (see `rung.models`). `created_at` is the server's UTC
time when the audit was stored; it is API metadata and not part of the deterministic report.
`POST /api/audits` runs synchronously and returns when the audit is finished.

```
$ curl -s -X POST localhost:8000/api/audits \
    -H 'Content-Type: application/json' \
    -d '{"source": "https://github.com/pallets/flask"}'
{"id": "3f2b9c0e6a7d4d0c9a51b7e2c4f8a1d3", "source": "https://github.com/pallets/flask",
 "created_at": "2026-11-10T21:30:00+00:00", "report": {"tool": {...}, "classification": {...}, ...}}
```

## Errors

Every error is JSON: `{"detail": "<message>", "code": "<code>"}`.

| Status | `code` | When |
| --- | --- | --- |
| 400 | `invalid_source` | Malformed source, unsupported scheme, credentials in URL, local path not a directory |
| 403 | `source_not_allowed` | Host not in the allowlist, local paths disabled, path outside the root |
| 404 | `audit_not_found` | Unknown audit id |
| 413 | `repo_too_large` | Clone exceeds `RUNG_MAX_REPO_MB` |
| 422 | `validation_error` | Bad body or query; `errors` lists `{loc, msg, type}` without the input |
| 500 | `audit_failed` | The engine raised; details are not returned |
| 502 | `clone_failed` | git could not clone (missing, private, or git unavailable) |
| 504 | `clone_timeout` | Clone exceeded `RUNG_CLONE_TIMEOUT` |
