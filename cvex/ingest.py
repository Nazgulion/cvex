from __future__ import annotations

import json
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session

from cvex.db.models import ConnectorState
from cvex.time import utcnow
from cvex.util import duration_seconds, sha256_text, stable_json_dumps


BATCH_SIZE = 1_000
batch_progress = ContextVar("batch_progress", default=None)


@dataclass(frozen=True)
class SeverityRecord:
    metric_type: str
    ordinal: int
    score: float | None
    vector: str | None
    label: str | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class CpeRecord:
    criteria: str | None
    part: str | None
    vendor: str | None
    product: str | None
    version: str | None
    vulnerable: bool | None
    match_criteria_id: str | None
    version_start: str | None
    version_end: str | None
    start_inclusive: bool | None
    end_inclusive: bool | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class MaterializedRecord:
    source: str
    cve_id: str
    source_modified: datetime | None
    published: datetime | None
    withdrawn: datetime | None
    status: str
    description: str | None
    payload: dict[str, Any]
    severities: tuple[SeverityRecord, ...] = ()
    cpes: tuple[CpeRecord, ...] = ()
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "sha256", sha256_text(stable_json_dumps(self.payload)))


@dataclass(frozen=True)
class BatchResult:
    seen: int
    changed: int


def batches(records: Iterable[MaterializedRecord], size: int = BATCH_SIZE):
    batch: list[MaterializedRecord] = []
    for record in records:
        batch.append(record)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def materialize_batch(session: Session, records: list[MaterializedRecord], run_id: str) -> BatchResult:
    """COPY one batch into temporary tables, then atomically merge current state."""
    if not records:
        return BatchResult(0, 0)
    sources = {record.source for record in records}
    if len(sources) != 1:
        raise ValueError("a materialization batch must contain exactly one source")
    source = next(iter(sources))

    _create_staging_tables(session)
    _copy(
        session,
        "payload_stage",
        ("source", "cve_id", "source_modified", "sha256", "payload_text", "published", "withdrawn", "status", "description"),
        [
            (
                row.source,
                row.cve_id,
                row.source_modified,
                row.sha256,
                stable_json_dumps(row.payload),
                row.published,
                row.withdrawn,
                row.status,
                row.description,
            )
            for row in records
        ],
    )
    if source == "nvd":
        _copy(
            session,
            "severity_stage",
            ("cve_id", "metric_type", "ordinal", "score", "vector", "label", "raw_text"),
            [
                (row.cve_id, severity.metric_type, severity.ordinal, severity.score, severity.vector, severity.label, stable_json_dumps(severity.raw))
                for row in records
                for severity in row.severities
            ],
        )
        _copy(
            session,
            "cpe_stage",
            (
                "cve_id", "criteria", "part", "vendor", "product", "version", "vulnerable", "match_criteria_id",
                "version_start", "version_end", "start_inclusive", "end_inclusive", "raw_text",
            ),
            [
                (
                    row.cve_id, cpe.criteria, cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.vulnerable,
                    cpe.match_criteria_id, cpe.version_start, cpe.version_end, cpe.start_inclusive, cpe.end_inclusive,
                    stable_json_dumps(cpe.raw),
                )
                for row in records
                for cpe in row.cpes
            ],
        )

    session.execute(
        text(
            """
            WITH upserted AS (
              INSERT INTO cvex.source_payload
                (source, cve_id, source_modified, fetched_at, sha256, payload, run_id)
              SELECT source, cve_id, source_modified, now(), sha256, payload_text::jsonb, :run_id
              FROM payload_stage
              ON CONFLICT (source, cve_id) DO UPDATE SET
                source_modified = EXCLUDED.source_modified,
                fetched_at = EXCLUDED.fetched_at,
                sha256 = EXCLUDED.sha256,
                payload = EXCLUDED.payload,
                run_id = EXCLUDED.run_id
              WHERE cvex.source_payload.sha256 IS DISTINCT FROM EXCLUDED.sha256
                AND (cvex.source_payload.source_modified IS NULL
                     OR EXCLUDED.source_modified >= cvex.source_payload.source_modified)
              RETURNING source, cve_id
            )
            INSERT INTO changed_stage (source, cve_id) SELECT source, cve_id FROM upserted
            """
        ),
        {"run_id": run_id},
    )
    changed = int(session.execute(text("SELECT count(*) FROM changed_stage")).scalar_one())

    if source == "cve":
        _merge_cve_vulnerabilities(session)
    else:
        _merge_nvd_vulnerabilities(session)
        _replace_nvd_children(session)
    session.commit()
    if batch_progress.get():
        batch_progress.get()(len(records), changed)
    return BatchResult(len(records), changed)


def _create_staging_tables(session: Session) -> None:
    session.execute(text("""
        CREATE TEMP TABLE payload_stage (
          source text, cve_id text, source_modified timestamptz, sha256 text, payload_text text,
          published timestamptz, withdrawn timestamptz, status text, description text
        ) ON COMMIT DROP;
        CREATE TEMP TABLE changed_stage (source text, cve_id text) ON COMMIT DROP;
        CREATE TEMP TABLE severity_stage (
          cve_id text, metric_type text, ordinal integer, score double precision,
          vector text, label text, raw_text text
        ) ON COMMIT DROP;
        CREATE TEMP TABLE cpe_stage (
          cve_id text, criteria text, part text, vendor text, product text, version text,
          vulnerable boolean, match_criteria_id text, version_start text, version_end text,
          start_inclusive boolean, end_inclusive boolean, raw_text text
        ) ON COMMIT DROP
    """))


def _copy(session: Session, table: str, columns: tuple[str, ...], rows: list[tuple[Any, ...]]) -> None:
    if not rows:
        return
    connection = session.connection().connection.driver_connection
    with connection.cursor() as cursor:
        with cursor.copy(f"COPY {table} ({', '.join(columns)}) FROM STDIN") as copy:
            for row in rows:
                copy.write_row(row)


def _merge_cve_vulnerabilities(session: Session) -> None:
    session.execute(text("""
        INSERT INTO cvex.vulnerability
          (cve_id, published, modified, withdrawn, status, description, description_source, updated_at)
        SELECT p.cve_id, p.published, p.source_modified, p.withdrawn, p.status,
               p.description, CASE WHEN p.description IS NULL THEN NULL ELSE 'cve' END, now()
        FROM payload_stage p JOIN changed_stage c USING (source, cve_id)
        ON CONFLICT (cve_id) DO UPDATE SET
          published = COALESCE(EXCLUDED.published, cvex.vulnerability.published),
          modified = COALESCE(EXCLUDED.modified, cvex.vulnerability.modified),
          withdrawn = EXCLUDED.withdrawn,
          status = EXCLUDED.status,
          description = COALESCE(EXCLUDED.description, cvex.vulnerability.description),
          description_source = CASE WHEN EXCLUDED.description IS NULL THEN cvex.vulnerability.description_source ELSE 'cve' END,
          updated_at = now()
    """))


def _merge_nvd_vulnerabilities(session: Session) -> None:
    session.execute(text("""
        INSERT INTO cvex.vulnerability
          (cve_id, published, modified, withdrawn, status, description, description_source, updated_at)
        SELECT p.cve_id, p.published, p.source_modified, p.withdrawn, p.status,
               p.description, CASE WHEN p.description IS NULL THEN NULL ELSE 'nvd' END, now()
        FROM payload_stage p JOIN changed_stage c USING (source, cve_id)
        ON CONFLICT (cve_id) DO UPDATE SET
          published = COALESCE(cvex.vulnerability.published, EXCLUDED.published),
          modified = CASE
            WHEN cvex.vulnerability.modified IS NULL THEN EXCLUDED.modified
            WHEN EXCLUDED.modified IS NULL THEN cvex.vulnerability.modified
            ELSE greatest(cvex.vulnerability.modified, EXCLUDED.modified)
          END,
          withdrawn = COALESCE(cvex.vulnerability.withdrawn, EXCLUDED.withdrawn),
          status = CASE WHEN EXISTS (
            SELECT 1 FROM cvex.source_payload sp WHERE sp.source='cve' AND sp.cve_id=EXCLUDED.cve_id
          ) THEN cvex.vulnerability.status ELSE EXCLUDED.status END,
          description = CASE WHEN cvex.vulnerability.description_source='cve'
            THEN cvex.vulnerability.description ELSE COALESCE(EXCLUDED.description, cvex.vulnerability.description) END,
          description_source = CASE WHEN cvex.vulnerability.description_source='cve' THEN 'cve'
            WHEN EXCLUDED.description IS NOT NULL THEN 'nvd' ELSE cvex.vulnerability.description_source END,
          updated_at = now()
    """))


def _replace_nvd_children(session: Session) -> None:
    session.execute(text("""
        DELETE FROM cvex.vulnerability_severity s
        USING changed_stage c WHERE c.source='nvd' AND s.cve_id=c.cve_id;
        INSERT INTO cvex.vulnerability_severity (cve_id, metric_type, ordinal, score, vector, label, raw)
        SELECT s.cve_id, s.metric_type, s.ordinal, s.score, s.vector, s.label, s.raw_text::jsonb
        FROM severity_stage s JOIN changed_stage c ON c.source='nvd' AND c.cve_id=s.cve_id;
        DELETE FROM cvex.affected_cpe a
        USING changed_stage c WHERE c.source='nvd' AND a.cve_id=c.cve_id;
        INSERT INTO cvex.affected_cpe
          (cve_id, cpe, cpe_criteria, cpe_part, cpe_vendor, cpe_product, cpe_version, vulnerable,
           match_criteria_id, version_start, version_end, start_inclusive, end_inclusive, raw_range)
        SELECT s.cve_id, s.criteria, s.criteria, s.part, s.vendor, s.product, s.version, s.vulnerable,
               s.match_criteria_id, s.version_start, s.version_end, s.start_inclusive, s.end_inclusive, s.raw_text::jsonb
        FROM cpe_stage s JOIN changed_stage c ON c.source='nvd' AND c.cve_id=s.cve_id
    """))


def finish_source_run(session: Session, run_id: str, source: str, config, details: dict[str, Any], checkpoint_type: str | None = None, checkpoint_value: str | None = None) -> None:
    now = utcnow()
    session.execute(text("UPDATE cvex.source_run SET status='succeeded', finished_at=:now, details=details || CAST(:details AS jsonb) WHERE id=:id"), {"now": now, "details": json.dumps(details), "id": run_id})
    state = session.get(ConnectorState, source)
    if state is None:
        state = ConnectorState(source=source, enabled=True)
        session.add(state)
    state.status = "idle"
    state.health = "healthy"
    state.last_success = now
    state.last_error = None
    state.error_count = 0
    if checkpoint_type is not None:
        state.checkpoint_type = checkpoint_type
        state.checkpoint_value = checkpoint_value
    state.freshness_sla_seconds = int(duration_seconds(config.sources[source].freshness_sla))
    state.retry_window_seconds = int(duration_seconds(config.sources[source].retry_window))
    state.updated_at = now
    session.commit()


def fail_source_run(session: Session, run_id: str, exc: Exception) -> None:
    session.rollback()
    session.execute(text("UPDATE cvex.source_run SET status='failed', finished_at=:now, details=details || CAST(:details AS jsonb) WHERE id=:id"), {"now": utcnow(), "details": json.dumps({"error": f"{type(exc).__name__}: {exc}"[:4000]}), "id": run_id})
    session.commit()
