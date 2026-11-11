"""FastAPI application: ``uvicorn --factory rung.api.app:create_app``.

There is no authentication in v1: the API clones and reads repositories on request, so it
must only listen on localhost or a trusted network (see docs/api.md).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from rung import __version__
from rung.api.sources import SourceError, SourcePolicy, checkout, resolve_source
from rung.api.store import AuditStore, StoredAudit
from rung.models import AuditReport, Rule

logger = logging.getLogger("rung.api")

Auditor = Callable[[Path, str], AuditReport]
SarifRenderer = Callable[[AuditReport], dict[str, Any]]


def _csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True)

    db_path: Path = Path("./rung.sqlite3")
    cors_origins: tuple[str, ...] = ("http://localhost:3000",)
    allowed_hosts: tuple[str, ...] = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")
    local_root: Path | None = None
    clone_timeout: int = Field(default=120, gt=0)
    max_repo_mb: int = Field(default=500, gt=0)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        values: dict[str, Any] = {}
        if env.get("RUNG_DB"):
            values["db_path"] = env["RUNG_DB"]
        if env.get("RUNG_CORS_ORIGINS"):
            values["cors_origins"] = _csv(env["RUNG_CORS_ORIGINS"])
        if env.get("RUNG_ALLOWED_HOSTS"):
            values["allowed_hosts"] = tuple(h.lower() for h in _csv(env["RUNG_ALLOWED_HOSTS"]))
        if env.get("RUNG_LOCAL_ROOT"):
            values["local_root"] = env["RUNG_LOCAL_ROOT"]
        if env.get("RUNG_CLONE_TIMEOUT"):
            values["clone_timeout"] = env["RUNG_CLONE_TIMEOUT"]
        if env.get("RUNG_MAX_REPO_MB"):
            values["max_repo_mb"] = env["RUNG_MAX_REPO_MB"]
        return cls(**values)

    def source_policy(self) -> SourcePolicy:
        return SourcePolicy(
            allowed_hosts=self.allowed_hosts,
            local_root=self.local_root,
            clone_timeout=self.clone_timeout,
            max_repo_bytes=self.max_repo_mb * 1024 * 1024,
        )


class AuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=2048)


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def _run_engine(path: Path, source: str) -> AuditReport:
    from rung.engine import run_audit

    return run_audit(path, source=source)


def _render_sarif(report: AuditReport) -> dict[str, Any]:
    from rung.report import to_sarif

    return to_sarif(report)


def _builtin_rules() -> Iterable[Rule]:
    from rung.registry import load_builtin_rules

    return load_builtin_rules()


def _stage_info() -> Sequence[BaseModel]:
    from rung.scoring.stages import STAGE_INFO

    return STAGE_INFO


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"detail": message, "code": code}, status_code=status_code)


def _envelope(audit: StoredAudit) -> dict[str, Any]:
    return {
        "id": audit.id,
        "source": audit.source,
        "created_at": audit.created_at,
        "report": audit.report,
    }


def create_app(
    settings: Settings | None = None,
    *,
    auditor: Auditor = _run_engine,
    sarif_renderer: SarifRenderer = _render_sarif,
    rule_loader: Callable[[], Iterable[Rule]] = _builtin_rules,
    stage_loader: Callable[[], Sequence[BaseModel]] = _stage_info,
) -> FastAPI:
    """Build the app. The keyword seams exist so tests can run without the real engine."""
    settings = settings or Settings.from_env()
    store = AuditStore(settings.db_path)
    policy = settings.source_policy()
    app = FastAPI(title="rung", version=__version__)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type"],
    )

    @app.exception_handler(SourceError)
    def source_error(_request: Request, exc: SourceError) -> JSONResponse:
        return _error(exc.status_code, exc.code, exc.message)

    @app.exception_handler(ApiError)
    def api_error(_request: Request, exc: ApiError) -> JSONResponse:
        return _error(exc.status_code, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    def validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo the rejected input: it may be a URL with embedded credentials.
        problems = [
            {"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg", ""), "type": e["type"]}
            for e in exc.errors()
        ]
        return JSONResponse(
            {"detail": "request validation failed", "code": "validation_error", "errors": problems},
            status_code=422,
        )

    def stored(audit_id: str) -> StoredAudit:
        audit = store.get(audit_id)
        if audit is None:
            raise ApiError(404, "audit_not_found", "no audit with this id")
        return audit

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/rules")
    def rules() -> dict[str, Any]:
        return {
            "items": [
                {
                    "id": r.id,
                    "title": r.title,
                    "dimension": r.dimension.value,
                    "stage": r.stage.value,
                    "severity": r.severity.value,
                    "confidence": r.confidence.value,
                    "weight": r.weight,
                    "description": r.description,
                    "remediation": r.remediation,
                }
                for r in rule_loader()
            ]
        }

    @app.get("/api/stages")
    def stages() -> dict[str, Any]:
        return {"items": [s.model_dump(mode="json") for s in stage_loader()]}

    @app.post("/api/audits", status_code=201)
    def create_audit(body: AuditRequest) -> dict[str, Any]:
        resolved = resolve_source(body.source, policy)
        with checkout(resolved, policy) as path:
            try:
                report = auditor(path, resolved.display)
            except Exception as exc:
                logger.error("audit failed: %s", type(exc).__name__)
                raise ApiError(500, "audit_failed", "the audit could not be completed") from exc
        return _envelope(store.add(resolved.display, report))

    @app.get("/api/audits")
    def list_audits(
        limit: int = Query(default=20, ge=1, le=100), offset: int = Query(default=0, ge=0)
    ) -> dict[str, Any]:
        return {
            "items": [
                {
                    "id": a.id,
                    "source": a.source,
                    "created_at": a.created_at,
                    "stage": a.stage,
                    "overall_score": a.overall_score,
                    "counts_by_severity": a.counts_by_severity,
                }
                for a in store.list(limit=limit, offset=offset)
            ]
        }

    @app.get("/api/audits/{audit_id}")
    def get_audit(audit_id: str) -> dict[str, Any]:
        return _envelope(stored(audit_id))

    @app.get("/api/audits/{audit_id}/sarif")
    def get_sarif(audit_id: str) -> dict[str, Any]:
        return sarif_renderer(AuditReport.model_validate(stored(audit_id).report))

    @app.delete("/api/audits/{audit_id}", status_code=204)
    def delete_audit(audit_id: str) -> Response:
        if not store.delete(audit_id):
            raise ApiError(404, "audit_not_found", "no audit with this id")
        return Response(status_code=204)

    return app
