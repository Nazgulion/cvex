"""Durable project scheduler and serial report executor."""
from __future__ import annotations

import json
import logging
import shutil
import threading
import time
from contextlib import contextmanager
from datetime import timedelta

from cvex.config import load_config
from cvex.db.models import Product, SbomDocument, Scan
from cvex.db.session import make_session_factory
from cvex.exporter import build_findings_payload, build_summary_payload, _render_findings_html, _write_findings_csv
from cvex.matcher import run_match
from cvex.time import utcnow
from cvex.workspace import audit, enqueue, next_occurrence, query, rows, safe_path, storage, telemetry

logger = logging.getLogger(__name__)


@contextmanager
def heartbeat(factory, name, state, details=None):
    stop = threading.Event()
    def beat():
        while not stop.is_set():
            try:
                with factory() as db:
                    telemetry(db, name, state, **(details or {}))
                    if details and details.get("job_id"):
                        query(db, "UPDATE cvex.report_job SET heartbeat_at=now() WHERE id=:id", id=details["job_id"])
                    db.commit()
            except Exception as exc:
                logger.warning("Heartbeat failed for %s (%s)", name, type(exc).__name__)
            stop.wait(3)
    thread = threading.Thread(target=beat, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=5)


def scheduler_tick(factory):
    with factory() as db:
        if not query(db, "SELECT pg_try_advisory_xact_lock(7401001)").scalar():
            return
        due = rows(db, "SELECT * FROM cvex.web_schedule WHERE enabled AND target LIKE 'project:%' AND next_run<=now() FOR UPDATE SKIP LOCKED")
        for schedule in due:
            try:
                enqueue(db, schedule["target"].split(":", 1)[1], "scheduled", schedule["next_run"])
            except ValueError as exc:
                audit(db, "scheduler", "schedule_skipped", target=schedule["target"], reason=str(exc))
            query(db, "UPDATE cvex.web_schedule SET next_run=:n WHERE target=:t", n=next_occurrence(schedule), t=schedule["target"])
        telemetry(db, "scheduler", "idle", phase="Checking project schedules", due=len(due))
        db.commit()


def cleanup_reports(factory):
    with factory() as db:
        if not query(db, "SELECT pg_try_advisory_xact_lock(7401003)").scalar():
            return
        old = rows(db, """SELECT * FROM (SELECT id,project_id,scan_id,artifacts,
          row_number() OVER(PARTITION BY project_id ORDER BY finished_at DESC,id DESC) position
          FROM cvex.report_job WHERE state IN ('succeeded','partial')) ranked WHERE position>30
          UNION ALL SELECT j.id,j.project_id,COALESCE(j.scan_id,s.scan_id),j.artifacts,0
          FROM cvex.report_job j LEFT JOIN cvex.report_snapshot s ON s.job_id=j.id
          WHERE j.state='failed' AND (j.scan_id IS NOT NULL OR s.job_id IS NOT NULL OR j.finished_at IS NULL)""")
        for job in old:
            # Persist deletion intent before touching files. Rollback leaves reports intact.
            relative = f"projects/{job['project_id']}/reports/{job['id']}"
            for path in (relative, relative + ".pending"):
                query(db, "INSERT INTO cvex.artifact_cleanup(path) VALUES(:p) ON CONFLICT DO NOTHING", p=path)
            query(db, """UPDATE cvex.report_job SET state=CASE WHEN state='failed' THEN state ELSE 'expired' END,
              artifacts=NULL,scan_id=NULL,finished_at=COALESCE(finished_at,now()) WHERE id=:id""", id=job["id"])
            query(db, "DELETE FROM cvex.report_snapshot WHERE job_id=:id", id=job["id"])
            if job["scan_id"]:
                sid = job["scan_id"]
                if not query(db, "SELECT 1 FROM cvex.report_job WHERE scan_id=:s", s=sid).scalar():
                    query(db, "DELETE FROM cvex.finding_evidence WHERE finding_id IN (SELECT id FROM cvex.vulnerability_finding WHERE scan_id=:s)", s=sid)
                    for table in ("report_export", "vulnerability_finding", "scan_component_result"):
                        query(db, f"DELETE FROM cvex.{table} WHERE scan_id=:s", s=sid)
                    query(db, "DELETE FROM cvex.scan WHERE id=:s", s=sid)
            audit(db, "retention", "report_expired", job_id=job["id"], project_id=job["project_id"])
        db.commit()
    drain_artifact_cleanup(factory)


def drain_artifact_cleanup(factory, path=None):
    with factory() as db:
        pending = rows(db, "SELECT path FROM cvex.artifact_cleanup WHERE (CAST(:p AS text) IS NULL OR path=:p) FOR UPDATE SKIP LOCKED", p=path)
        for item in pending:
            try:
                directory = safe_path(item["path"])
                if directory != storage() / item["path"]:
                    raise ValueError("Refusing cleanup through a symlink")
                if directory.exists():
                    shutil.rmtree(directory)
            except (OSError, ValueError) as exc:
                logger.warning("Artifact cleanup deferred (%s)", type(exc).__name__)
                continue
            query(db, "DELETE FROM cvex.artifact_cleanup WHERE path=:p", p=item["path"])
        db.commit()
        return bool(query(db, "SELECT 1 FROM cvex.artifact_cleanup WHERE (CAST(:p AS text) IS NULL OR path=:p) LIMIT 1", p=path).first())


def report_tick(factory, config):
    # Dedicated connection holds a session advisory lock through all report transactions.
    engine = factory.kw["bind"]
    with engine.connect() as lock:
        if not query(lock, "SELECT pg_try_advisory_lock(7401002)").scalar():
            return
        try:
            _report_tick(factory, config)
        finally:
            query(lock, "SELECT pg_advisory_unlock(7401002)")


def _report_tick(factory, config):
    with factory() as db:
        # The executor lock ensures an old process cannot continue concurrently.
        query(db, """UPDATE cvex.report_job SET state=CASE WHEN attempts>=3 THEN 'failed' ELSE 'queued' END,
          error='Worker interrupted; recovering durable job',available_at=now()
          WHERE state IN ('scanning','exporting')""")
        job = query(db, """SELECT j.*,s.payload frozen_payload,s.scan_id snapshot_scan_id
          FROM cvex.report_job j LEFT JOIN cvex.report_snapshot s ON s.job_id=j.id
          WHERE j.state='queued' AND j.available_at<=now() ORDER BY j.created_at
          FOR UPDATE OF j SKIP LOCKED LIMIT 1""").mappings().first()
        if not job:
            telemetry(db, "report-worker", "idle", phase="Waiting for report jobs")
            db.commit()
            return
        job = dict(job)
        job["scan_id"] = job["snapshot_scan_id"] or job["scan_id"]
        query(db, "UPDATE cvex.report_job SET state='scanning',started_at=COALESCE(started_at,now()),heartbeat_at=now(),attempts=attempts+1 WHERE id=:id", id=job["id"])
        db.commit()
    details = {"job_id": str(job["id"]), "project_id": str(job["project_id"]), "phase": "scanning"}
    try:
        with heartbeat(factory, "report-worker", "running", details):
            if not job["frozen_payload"]:
                last_progress = [0.0]
                def progress(done, total):
                    details.update(processed=done, total=total)
                    if time.monotonic()-last_progress[0] < 2 and done != total:
                        return
                    with factory() as db:
                        query(db, "UPDATE cvex.report_job SET progress=:p,total=:t WHERE id=:id", p=done, t=total, id=job["id"])
                        db.commit()
                    last_progress[0] = time.monotonic()
                with factory() as db:
                    db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
                    version = query(db, "SELECT v.*,p.company,p.name FROM cvex.project_version v JOIN cvex.project p ON p.id=v.project_id WHERE v.id=:v", v=job["version_id"]).mappings().one()
                    sid = run_match(db, config, str(version["sbom_id"]), sources=["cve", "nvd"], commit=False, progress=progress)
                    scan = db.get(Scan, sid)
                    sbom = db.get(SbomDocument, version["sbom_id"])
                    # Presentation metadata belongs to the project, even for deduplicated SBOMs.
                    product = Product(client_name=version["company"], product_name=version["name"], release_version=version["label"])
                    findings = build_findings_payload(db, config, scan, sbom, product, str(job["id"]))
                    summary = build_summary_payload(db, config, scan, sbom, product, str(job["id"]))
                    frozen = {"findings": findings, "summary": summary, "scan_status": scan.status}
                    # Commit the snapshot and frozen payload together, without updating the separately heartbeating job row.
                    query(db, "INSERT INTO cvex.report_snapshot(job_id,scan_id,payload) VALUES(:j,:s,CAST(:p AS jsonb))", j=job["id"], s=sid, p=json.dumps(frozen))
                    db.commit()
                job["frozen_payload"] = frozen
                job["scan_id"] = sid
            details["phase"] = "exporting"
            frozen = job["frozen_payload"]
            with factory() as db:
                query(db, "UPDATE cvex.report_job SET state='exporting',scan_id=:s WHERE id=:id", s=job["scan_id"], id=job["id"])
                db.commit()
            relative = f"projects/{job['project_id']}/reports/{job['id']}"
            directory = safe_path(relative)
            temporary = safe_path(relative + ".pending")
            temporary.mkdir(parents=True, exist_ok=True)
            (temporary / "scan-summary.json").write_text(json.dumps(frozen["summary"], indent=2), encoding="utf-8")
            (temporary / "findings.json").write_text(json.dumps(frozen["findings"], indent=2), encoding="utf-8")
            _write_findings_csv(temporary / "findings.csv", frozen["findings"]["findings"])
            (temporary / "findings.html").write_text(_render_findings_html(frozen["findings"]), encoding="utf-8")
            if not directory.exists():
                temporary.rename(directory)
            else:
                shutil.rmtree(temporary)
            artifacts = {"html": relative+"/findings.html", "csv": relative+"/findings.csv", "json": relative+"/findings.json", "summary": relative+"/scan-summary.json"}
            brief = {"counts": frozen["summary"].get("counts", {}), "source_freshness": frozen["summary"].get("source_freshness", {})}
            with factory() as db:
                query(db, "UPDATE cvex.report_job SET state=:state,finished_at=now(),error=:error,summary=CAST(:s AS jsonb),artifacts=CAST(:a AS jsonb) WHERE id=:id",
                      state="partial" if frozen.get("scan_status") == "partial" else "succeeded",
                      error="Some components could not be assessed; see report errors" if frozen.get("scan_status") == "partial" else None,
                      s=json.dumps(brief), a=json.dumps(artifacts), id=job["id"])
                audit(db, "report-worker", "report_published", project_id=job["project_id"], job_id=job["id"])
                db.commit()
    except Exception as exc:
        with factory() as db:
            # Snapshot is durable even if the process failed before attaching it to the job.
            query(db, """UPDATE cvex.report_job SET state=CASE WHEN attempts>=3 THEN 'failed' ELSE 'queued' END,
              error=:e,available_at=now()+interval '30 seconds'*attempts,
              scan_id=COALESCE(scan_id,(SELECT scan_id FROM cvex.report_snapshot WHERE job_id=:id)) WHERE id=:id""", id=job["id"], e=f"{type(exc).__name__}: {exc}"[:1000])
            audit(db, "report-worker", "report_attempt_failed", job_id=job["id"])
            db.commit()
    cleanup_reports(factory)


def serve_background(kind):
    config = load_config()
    factory = make_session_factory(config)
    storage().mkdir(parents=True, exist_ok=True)
    last_storage_sample = 0
    while True:
        try:
            if kind == "scheduler":
                scheduler_tick(factory)
                if time.monotonic()-last_storage_sample > 60:
                    total = sum(p.stat().st_size for p in storage().glob("projects/*/reports/*/*") if p.is_file())
                    with factory() as db:
                        telemetry(db,"storage","healthy",phase="Project report storage",report_bytes=total)
                        db.commit()
                    cleanup_reports(factory)
                    last_storage_sample = time.monotonic()
            else:
                report_tick(factory, config)
        except Exception as exc:
            print(f"{kind}: {type(exc).__name__}: {exc}", flush=True)
        time.sleep(2)
