"""Shared workspace persistence, credentials and calendar policy."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from croniter import croniter
from cryptography.fernet import Fernet
from sqlalchemy import text

from cvex.time import utcnow


def query(db, sql, **params):
    return db.execute(text(sql), params)


def rows(db, sql, **params):
    return [dict(r) for r in query(db, sql, **params).mappings()]


def audit(db, actor, action, **details):
    query(db, "INSERT INTO cvex.web_audit(actor,action,details) VALUES(:a,:b,CAST(:d AS jsonb))",
          a=actor, b=action, d=json.dumps(details, default=str))


def password_hash(password):
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password, encoded):
    try:
        salt, digest = encoded.split(":")
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
        return hmac.compare_digest(actual.hex(), digest)
    except (ValueError, TypeError):
        return False


def cipher():
    key = os.environ.get("CVEX_ENCRYPTION_KEY")
    if not key:
        raise ValueError("CVEX_ENCRYPTION_KEY must be configured to store API keys")
    return Fernet(key.encode())


def storage():
    return Path(os.environ.get("CVEX_WORKSPACE_ROOT", "data/workspace")).resolve()


def safe_path(relative):
    root = storage()
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or path == root:
        raise ValueError("Invalid artifact path")
    return path


def next_occurrence(schedule, after=None):
    after = after or utcnow()
    if schedule["mode"] == "interval":
        return after + timedelta(seconds=schedule["interval_seconds"])
    zone = ZoneInfo(schedule["timezone"])
    # Iterate local wall time, then explicitly resolve DST gaps and folds.
    iterator = croniter(schedule["expression"], after.astimezone(zone).replace(tzinfo=None))
    for _ in range(10000):
        local = iterator.get_next(datetime)
        aware = local.replace(tzinfo=zone, fold=0)
        utc = aware.astimezone(timezone.utc)
        if utc.astimezone(zone).replace(tzinfo=None) != local:
            continue
        if utc > after:
            return utc
    raise ValueError("No valid schedule occurrence found")


def enqueue(db, project_id, trigger="manual", scheduled_at=None):
    project = query(db, "SELECT * FROM cvex.project WHERE id=:id FOR UPDATE", id=project_id).mappings().first()
    if not project:
        raise ValueError("Project not found")
    if not project["active_version_id"]:
        raise ValueError("Upload and activate an SBOM first")
    existing = query(db, "SELECT id FROM cvex.report_job WHERE project_id=:id AND state IN ('queued','scanning','exporting')", id=project_id).scalar()
    if existing:
        if trigger == "scheduled":
            audit(db, "scheduler", "schedule_overlap_skipped", project_id=project_id, scheduled_at=scheduled_at)
        return str(existing)
    value = query(db, """INSERT INTO cvex.report_job(project_id,version_id,trigger,scheduled_at)
      VALUES(:p,:v,:t,:s) ON CONFLICT(project_id,scheduled_at) DO UPDATE SET trigger=cvex.report_job.trigger RETURNING id""",
      p=project_id, v=project["active_version_id"], t=trigger, s=scheduled_at).scalar()
    return str(value)


def telemetry(db, name, state, phase=None, version=None, **details):
    query(db, """INSERT INTO cvex.worker_telemetry(name,state,phase,details,applied_version)
      VALUES(:n,:s,:p,CAST(:d AS jsonb),:v) ON CONFLICT(name) DO UPDATE SET state=:s,
      phase=:p,details=CAST(:d AS jsonb),heartbeat_at=now(),applied_version=COALESCE(:v,cvex.worker_telemetry.applied_version)""",
      n=name, s=state, p=phase, v=version, d=json.dumps(details, default=str))
