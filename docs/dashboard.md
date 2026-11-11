# rung dashboard

A Next.js (App Router, TypeScript, Tailwind CSS) front end for the rung API. It lives in
`web/` and talks to the API from the browser, so the API must allow the dashboard's origin
(`RUNG_CORS_ORIGINS`).

## Run it

**Development**

```bash
rung serve                 # API on http://localhost:8000
cd web && npm install
npm run dev                # dashboard on http://localhost:3000
```

**Production build**

```bash
cd web
npm run lint && npm run build
npm run start -- -p 3000
```

**Containers**

```bash
docker compose up --build  # API on 127.0.0.1:8000, dashboard on 127.0.0.1:3000
```

Both images are multi-stage, run as a non-root user, have a healthcheck and a read-only
root filesystem. Audit history is kept in the `rung-data` volume.

## Configuration

| Variable | Where | Default | Purpose |
| --- | --- | --- | --- |
| `NEXT_PUBLIC_RUNG_API_URL` | `web` build time (build arg in `web/Dockerfile`) | `http://localhost:8000` | URL the browser uses to reach the API |
| `NEXT_OUTPUT` | `web` build time | unset | `standalone` produces the self-contained server the image runs |
| `RUNG_CORS_ORIGINS` | API | | Origins allowed to call the API, e.g. `http://localhost:3000` |
| `RUNG_DB` | API | `/data/rung.sqlite3` in the image | SQLite history file |

`NEXT_PUBLIC_RUNG_API_URL` is inlined into the bundle, so changing it needs a rebuild.

## Pages

| Path | What it shows |
| --- | --- |
| `/` | Audit form (https URLs only), recent audits, link to the sample |
| `/audits/{id}` | A stored report, loaded from `GET /api/audits/{id}` |
| `/sample` | The same report view rendered from `web/public/sample-report.json`; needs no API |
| `/rules` | Rule catalogue from `GET /api/rules`, grouped by dimension, filterable by stage |
| `/stages` | The four stages from `GET /api/stages` |

The report view (`web/src/components/ReportView.tsx`) is shared by `/audits/{id}` and
`/sample`. Top to bottom: header with score and JSON/SARIF downloads; the ladder (one rung
per stage, fill = `classification.progress[].fulfillment`, dashed line =
`classification.threshold`, "You are here" on `classification.stage`); dimension scores;
the next-steps checklist grouped by priority (ticks are stored per audit in the browser's
localStorage); findings with filters, sorting and remediation; every rule's outcome and
evidence; the summary.

Every page says so plainly when the API is down and points at `rung serve`. Report strings
are rendered as text only.

## Regenerating the sample report

```bash
rung audit <repo> --format json --output web/public/sample-report.json
cd web && npm run build
```

The file is imported at build time, so rebuild after replacing it. The view depends only on
the `AuditReport` schema (`src/rung/models.py`, mirrored in `web/src/lib/types.ts`).
