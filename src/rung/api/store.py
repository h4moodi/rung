"""SQLite audit history. One short-lived connection per call, parameterised SQL only."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rung.models import AuditReport

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    stage TEXT NOT NULL,
    overall_score REAL NOT NULL,
    counts TEXT NOT NULL,
    report TEXT NOT NULL
)
"""


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class StoredAudit:
    id: str
    source: str
    created_at: str
    stage: str
    overall_score: float
    counts_by_severity: dict[str, int]
    report: dict[str, Any] | None = None


class AuditStore:
    """``created_at`` is API metadata (wall clock); it is not part of the report."""

    def __init__(self, path: Path, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._path = Path(path)
        self._clock = clock
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def add(self, source: str, report: AuditReport) -> StoredAudit:
        payload = report.model_dump(mode="json")
        audit = StoredAudit(
            id=uuid.uuid4().hex,
            source=source,
            created_at=self._clock().astimezone(UTC).isoformat(timespec="seconds"),
            stage=report.classification.stage.value,
            overall_score=report.overall_score,
            counts_by_severity=payload["summary"]["counts_by_severity"],
            report=payload,
        )
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO audits (id, source, created_at, stage, overall_score, counts, report)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    audit.id,
                    audit.source,
                    audit.created_at,
                    audit.stage,
                    audit.overall_score,
                    json.dumps(audit.counts_by_severity, sort_keys=True),
                    json.dumps(payload),
                ),
            )
        return audit

    def list(self, *, limit: int = 20, offset: int = 0) -> list[StoredAudit]:
        """Newest first, without the report bodies."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, source, created_at, stage, overall_score, counts FROM audits"
                " ORDER BY seq DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [StoredAudit(*row[:5], counts_by_severity=json.loads(row[5])) for row in rows]

    def get(self, audit_id: str) -> StoredAudit | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, source, created_at, stage, overall_score, counts, report"
                " FROM audits WHERE id = ?",
                (audit_id,),
            ).fetchone()
        if row is None:
            return None
        return StoredAudit(
            *row[:5], counts_by_severity=json.loads(row[5]), report=json.loads(row[6])
        )

    def delete(self, audit_id: str) -> bool:
        with self._connect() as conn:
            return conn.execute("DELETE FROM audits WHERE id = ?", (audit_id,)).rowcount > 0
