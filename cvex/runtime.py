"""Database-driven source schedules with exclusive execution and live heartbeats."""
import logging
import time

from cvex.config import load_config
from cvex.db.session import make_session_factory
from cvex.jobs import heartbeat
from cvex.source_lock import source_lock
from cvex.sync_history import error_type, reconcile_sync_history, start_sync_history
from cvex.time import utcnow
from cvex.util import duration_seconds
from cvex.workspace import cipher, next_occurrence, query, telemetry

logger = logging.getLogger(__name__)


def source_tick(factory, source):
    from cvex.workers import cve_sync_cycle, nvd_sync_cycle
    from cvex.ingest import batch_progress

    with source_lock(factory.kw["bind"], source):
        config = load_config()
        original = config.sources[source]
        with factory() as db:
            reconcile_sync_history(db, source)
            query(db, """INSERT INTO cvex.web_schedule(target,mode,enabled,interval_seconds,next_run)
              VALUES(:s,'interval',:e,:i,now()) ON CONFLICT DO NOTHING""",
              s=source, e=original.enabled, i=int(duration_seconds(original.sync_interval)))
            query(db, "INSERT INTO cvex.worker_setting(source) VALUES(:s) ON CONFLICT DO NOTHING", s=source)
            schedule = dict(query(db, "SELECT * FROM cvex.web_schedule WHERE target=:s", s=source).mappings().one())
            setting = query(db, "SELECT * FROM cvex.worker_setting WHERE source=:s", s=source).mappings().one()
            values = original.model_dump()
            values.update(setting["settings"])
            values["enabled"] = schedule["enabled"]
            if setting["encrypted_key"] is not None:
                values["api_key"] = cipher().decrypt(setting["encrypted_key"].encode()).decode() if setting["encrypted_key"] else None
            config.sources[source] = type(original).model_validate(values)
            due = schedule["enabled"] and (not schedule["next_run"] or schedule["next_run"] <= utcnow())
            telemetry(db, source, "running" if due else "idle" if schedule["enabled"] else "paused",
                      phase="Starting synchronization" if due else "Waiting for schedule",
                      version=setting["version"], schedule_version=schedule["version"], next_run=schedule["next_run"])
            db.commit()
        if not due:
            return
        details = {"processed": 0, "changed": 0, "phase": "Fetching upstream records", "schedule_version": schedule["version"]}

        def on_batch(seen, changed):
            details["processed"] += seen
            details["changed"] += changed
            details["phase"] = "Materializing source batches"

        with factory() as db:
            history_id = start_sync_history(db, source)
            db.commit()
        token = batch_progress.set(on_batch)
        try:
            with heartbeat(factory, source, "running", details):
                result = (cve_sync_cycle if source == "cve" else nvd_sync_cycle)(factory, config)
        except Exception as exc:
            with factory() as db:
                query(db, """UPDATE cvex.sync_history SET status='failed',finished_at=now(),
                  processed=:p,changed=:c,error_type=:e WHERE id=:id""",
                  id=history_id, p=details["processed"], c=details["changed"], e=type(exc).__name__)
                db.commit()
            raise
        finally:
            batch_progress.reset(token)
        with factory() as db:
            state = query(db, "SELECT status,next_retry_at,last_error FROM cvex.connector_state WHERE source=:s", s=source).mappings().one()
            history_status = "deferred" if ": retry_wait " in result.message else "failed" if state["status"] == "retrying" else "succeeded"
            query(db, """UPDATE cvex.sync_history SET status=:status,finished_at=now(),
              processed=:p,changed=:c,error_type=:e WHERE id=:id""",
              id=history_id, status=history_status, p=details["processed"], c=details["changed"],
              e=error_type(state["last_error"]) if history_status != "succeeded" else None)
            next_run = state["next_retry_at"] if state["status"] == "retrying" else next_occurrence(schedule)
            query(db, "UPDATE cvex.web_schedule SET next_run=:n WHERE target=:s AND version=:v", n=next_run, s=source, v=schedule["version"])
            telemetry(db, source, state["status"], phase="Cycle complete", version=setting["version"],
                      **{k: v for k, v in details.items() if k != "phase"})
            db.commit()
        logger.info("%s", result.message)


def source_loop(source):
    logging.basicConfig(level=logging.INFO)
    factory = make_session_factory(load_config())
    while True:
        try:
            source_tick(factory, source)
        except Exception as exc:
            logger.warning("%s runtime failure (%s)", source, type(exc).__name__)
        time.sleep(2)
