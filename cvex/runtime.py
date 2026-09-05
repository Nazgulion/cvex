"""Database-driven source schedules with exclusive source execution and live heartbeats."""
import time
from datetime import timedelta

from cvex.config import load_config
from cvex.db.session import make_session_factory
from cvex.jobs import heartbeat
from cvex.time import utcnow
from cvex.util import duration_seconds
from cvex.workspace import cipher, next_occurrence, query, telemetry


def source_loop(source):
    from cvex.workers import cve_sync_cycle, nvd_sync_cycle
    from cvex.ingest import batch_progress
    factory = make_session_factory(load_config())
    while True:
        try:
            with factory.kw["bind"].connect() as lock:
                lock_id = 7401010 if source == "cve" else 7401011
                if not query(lock, "SELECT pg_try_advisory_lock(:id)", id=lock_id).scalar():
                    time.sleep(2)
                    continue
                try:
                    config = load_config()
                    original = config.sources[source]
                    with factory() as db:
                        query(db, """INSERT INTO cvex.web_schedule(target,mode,enabled,interval_seconds,next_run)
                          VALUES(:s,'interval',:e,:i,now()) ON CONFLICT DO NOTHING""", s=source, e=original.enabled, i=int(duration_seconds(original.sync_interval)))
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
                                  phase="Starting synchronization" if due else "Waiting for schedule", version=setting["version"], schedule_version=schedule["version"], next_run=schedule["next_run"])
                        db.commit()
                    if due:
                        details = {"processed": 0, "changed": 0, "phase": "Fetching upstream records", "schedule_version": schedule["version"]}
                        def on_batch(seen, changed):
                            details["processed"] += seen
                            details["changed"] += changed
                            details["phase"] = "Materializing source batches"
                        token = batch_progress.set(on_batch)
                        try:
                            with heartbeat(factory, source, "running", details):
                                result = (cve_sync_cycle if source == "cve" else nvd_sync_cycle)(factory, config)
                        finally:
                            batch_progress.reset(token)
                        with factory() as db:
                            state = query(db, "SELECT status,next_retry_at FROM cvex.connector_state WHERE source=:s", s=source).mappings().one()
                            next_run = state["next_retry_at"] if state["status"] == "retrying" else next_occurrence(schedule)
                            query(db, "UPDATE cvex.web_schedule SET next_run=:n WHERE target=:s AND version=:v", n=next_run, s=source, v=schedule["version"])
                            telemetry(db, source, state["status"], phase="Cycle complete", version=setting["version"], **{k:v for k,v in details.items() if k != "phase"})
                            db.commit()
                        print(result.message, flush=True)
                finally:
                    query(lock, "SELECT pg_advisory_unlock(:id)", id=lock_id)
        except Exception as exc:
            # Do not emit settings, keys, or upstream request headers.
            print(f"{source}: runtime failure ({type(exc).__name__})", flush=True)
        time.sleep(2)
