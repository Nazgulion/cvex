from datetime import datetime, timedelta, timezone
import os

import pytest

from cvex.sync_history import upcoming_runs, error_type, prune_sync_history, start_sync_history
from cvex.workspace import query
from test_project_deletion import workspace


def test_upcoming_uses_persisted_next_run_and_paused_has_no_runs():
    now = datetime(2026, 9, 9, 11, tzinfo=timezone.utc)
    saved = {"enabled": True, "mode": "interval", "interval_seconds": 7200,
             "next_run": now + timedelta(minutes=15)}
    result = upcoming_runs(saved, now=now)
    assert len(result) == 5 and result[0] == saved["next_run"]
    assert result[-1] == result[0] + timedelta(hours=8)
    assert upcoming_runs({**saved, "enabled": False}, now=now) == []
    running = upcoming_runs(saved, now=now, running=True)
    assert running[0] == now + timedelta(hours=2)


def test_overdue_and_retry_schedule_does_not_invent_five_missed_runs():
    now = datetime(2026, 9, 9, 11, tzinfo=timezone.utc)
    saved = {"enabled": True, "mode": "interval", "interval_seconds": 7200,
             "next_run": now - timedelta(days=3)}
    result = upcoming_runs(saved, now=now)
    assert result[0] == saved["next_run"]
    assert result[1] == now + timedelta(hours=2)
    saved["next_run"] = now + timedelta(seconds=30)
    assert upcoming_runs(saved, now=now)[0] == saved["next_run"]


def test_cron_preview_preserves_saved_time_and_dst_policy():
    now = datetime(2026, 10, 24, 2, tzinfo=timezone.utc)
    saved = {"enabled": True, "mode": "cron", "expression": "30 2 * * *", "timezone": "Europe/Belgrade",
             "next_run": datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)}
    result = upcoming_runs(saved, now=now)
    assert result[0] == saved["next_run"]
    assert result[1] == datetime(2026, 10, 26, 1, 30, tzinfo=timezone.utc)
    assert len(result) == len(set(result)) == 5


def test_error_types_never_expose_upstream_urls_or_credentials():
    assert error_type("HTTPError: https://private.example?apiKey=secret") == "HTTPError"
    assert error_type("https://private.example?apiKey=secret") == "https"
    assert error_type("invalid token secret") is None
    assert error_type(None) is None


integration = pytest.mark.skipif(not os.getenv("CVEX_TEST_DATABASE_URL"), reason="requires disposable PostgreSQL")


@integration
def test_history_api_bounds_pagination_access_and_real_next_run(workspace):
    factory, clients, *_ = workspace
    with factory() as db:
        query(db, "DELETE FROM cvex.sync_history")
        query(db, """INSERT INTO cvex.sync_history(source,status,started_at,finished_at,processed,changed)
          SELECT 'nvd','succeeded',now()-i*interval '1 hour',now()-i*interval '1 hour'+interval '21 seconds',410,300
          FROM generate_series(1,31) i""")
        query(db, """INSERT INTO cvex.sync_history(source,status,started_at) VALUES
          ('nvd','failed',now()-interval '11 days'),('cve','succeeded',now())""")
        query(db, """INSERT INTO cvex.web_schedule(target,enabled,mode,interval_seconds,next_run)
          VALUES('nvd',true,'interval',7200,now()+interval '15 minutes')
          ON CONFLICT(target) DO UPDATE SET enabled=true,mode='interval',interval_seconds=7200,next_run=excluded.next_run""")
        db.commit()
    api = clients["admin"]
    response = api.get('/api/v1/admin/sync-history/nvd')
    assert response.status_code == 200, response.text
    first = response.json()
    assert first["totals"]["runs"] == 31 and first["retention_days"] == 10
    assert len(first["history"]) == 25
    assert first["history"][0]["processed"] == 410 and first["history"][0]["duration_seconds"] == 21
    assert first["schedule"]["upcoming"][0] == first["schedule"]["next_run"]
    assert len(first["schedule"]["upcoming"]) == 5
    second = api.get('/api/v1/admin/sync-history/nvd?offset=25').json()
    assert len(second["history"]) == 6
    assert not {r["id"] for r in first["history"]} & {r["id"] for r in second["history"]}
    assert second["latest"] == first["latest"]
    assert api.get('/api/v1/admin/sync-history/nvd?offset=-1').status_code == 422
    assert api.get('/api/v1/admin/sync-history/osv').status_code == 422
    assert clients["user"].get('/api/v1/admin/sync-history/nvd').status_code == 403
    clients["user"].cookies.clear()
    assert clients["user"].get('/api/v1/admin/sync-history/nvd').status_code == 401
    with factory() as db:
        query(db, "UPDATE cvex.web_schedule SET enabled=false WHERE target='nvd'")
        db.commit()
    assert api.get('/api/v1/admin/sync-history/nvd').json()["schedule"]["upcoming"] == []
    assert api.get('/api/v1/schedules/nvd').json()["upcoming"] == []


@integration
def test_retention_preserves_running_attempts_and_source_provenance(workspace):
    factory, *_ = workspace
    with factory() as db:
        query(db, "DELETE FROM cvex.sync_history")
        old = query(db, """INSERT INTO cvex.sync_history(source,status,started_at)
          VALUES('nvd','succeeded',now()-interval '11 days') RETURNING id""").scalar()
        running = query(db, """INSERT INTO cvex.sync_history(source,status,started_at)
          VALUES('nvd','running',now()-interval '11 days') RETURNING id""").scalar()
        before = query(db, "SELECT count(*) FROM cvex.source_run").scalar()
        assert prune_sync_history(db) == 1
        assert query(db, "SELECT count(*) FROM cvex.sync_history WHERE id=:id", id=old).scalar() == 0
        assert query(db, "SELECT status FROM cvex.sync_history WHERE id=:id", id=running).scalar() == 'running'
        active = start_sync_history(db, 'nvd')
        assert query(db, "SELECT count(*) FROM cvex.sync_history WHERE id=:id", id=running).scalar() == 0
        assert query(db, "SELECT status FROM cvex.sync_history WHERE id=:id", id=active).scalar() == 'running'
        assert query(db, "SELECT count(*) FROM cvex.source_run").scalar() == before
        db.rollback()


@integration
def test_worker_cycles_record_fetch_failures_counts_and_independent_recovery(workspace, monkeypatch):
    import cvex.workers as workers
    from cvex.runtime import source_tick
    from cvex.ingest import batch_progress, finish_source_run
    factory, clients, *_ = workspace
    with factory() as db:
        query(db, "DELETE FROM cvex.sync_history")
        query(db, "DELETE FROM cvex.worker_setting")
        query(db, "DELETE FROM cvex.connector_state WHERE source IN ('nvd','cve')")
        for source in ('nvd', 'cve'):
            query(db, """INSERT INTO cvex.web_schedule(target,enabled,mode,interval_seconds,next_run)
              VALUES(:s,true,'interval',7200,now()) ON CONFLICT(target) DO UPDATE SET enabled=true,next_run=now()""", s=source)
        db.commit()

    def fail_fetch(*args, **kwargs):
        raise RuntimeError('upstream fetch failed: private-credential')

    def succeed(db, config, **kwargs):
        batch_progress.get()(7, 4)
        run_id = query(db, "INSERT INTO cvex.source_run(source,run_type,status) VALUES('cve','sync','running') RETURNING id").scalar()
        finish_source_run(db, str(run_id), 'cve', config, {})
        return str(run_id), 7, None, 'checkpoint'

    monkeypatch.setattr(workers, 'ingest_nvd_incremental', fail_fetch)
    monkeypatch.setattr(workers, 'ingest_cve_incremental', succeed)
    source_tick(factory, 'nvd')
    source_tick(factory, 'cve')
    with factory() as db:
        runs = {r['source']: r for r in query(db, "SELECT * FROM cvex.sync_history").mappings()}
        assert runs['nvd']['status'] == 'failed' and runs['nvd']['error_type'] == 'RuntimeError'
        assert runs['nvd']['processed'] == 0 and runs['nvd']['finished_at'] is not None
        assert runs['cve']['status'] == 'succeeded'
        assert runs['cve']['processed'] == 7 and runs['cve']['changed'] == 4
        retry = query(db, "SELECT next_retry_at FROM cvex.connector_state WHERE source='nvd'").scalar()
        assert query(db, "SELECT next_run FROM cvex.web_schedule WHERE target='nvd'").scalar() == retry
    response = clients['admin'].get('/api/v1/admin/sync-history/nvd')
    assert 'private-credential' not in response.text
    assert response.json()['schedule']['upcoming'][0] == retry.isoformat()
    # An idle poll does not create another history entry.
    source_tick(factory, 'cve')
    with factory() as db:
        assert query(db, "SELECT count(*) FROM cvex.sync_history WHERE source='cve'").scalar() == 1
        query(db, "UPDATE cvex.web_schedule SET enabled=false WHERE target='cve'")
        abandoned = query(db, "INSERT INTO cvex.sync_history(source,status) VALUES('cve','running') RETURNING id").scalar()
        db.commit()
    source_tick(factory, 'cve')
    with factory() as db:
        assert query(db, "SELECT status FROM cvex.sync_history WHERE id=:id", id=abandoned).scalar() == 'interrupted'
