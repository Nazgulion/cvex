"""Small, expiring worker activity records; never prune source-run provenance."""
import re

from cvex.time import utcnow
from cvex.workspace import next_occurrence, query


def upcoming_runs(schedule, *, now=None, running=False):
    if not schedule.get("enabled"):
        return []
    now = now or utcnow()
    first = (next_occurrence(schedule, now) if running else
             schedule.get("next_run") or next_occurrence(schedule, now))
    result = [first]
    for _ in range(4):
        result.append(next_occurrence(schedule, max(result[-1], now)))
    return result


def error_type(value):
    name = (value or "").split(":", 1)[0]
    return name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]*", name) else None


def prune_sync_history(db):
    # Running attempts are reconciled by the source lease holder after an interruption.
    return query(db, """DELETE FROM cvex.sync_history
      WHERE status <> 'running' AND started_at < now()-interval '10 days'""").rowcount


def reconcile_sync_history(db, source):
    # Caller holds the source lease: any previously running attempt has been abandoned.
    result = query(db, """UPDATE cvex.sync_history SET status='interrupted',error_type='WorkerInterrupted'
      WHERE source=:s AND status='running'""", s=source)
    return result.rowcount


def start_sync_history(db, source):
    reconcile_sync_history(db, source)
    prune_sync_history(db)
    return query(db, "INSERT INTO cvex.sync_history(source,status) VALUES(:s,'running') RETURNING id", s=source).scalar()
