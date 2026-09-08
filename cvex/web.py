"""Authenticated HTTP API. Background work is claimed by dedicated processes."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field
from croniter import croniter

from cvex.config import load_config
from cvex.db.session import make_session_factory
from cvex.sbom import import_spdx
from cvex.spdx_validation import validate_spdx
from cvex.time import utcnow
from cvex.workspace import audit, cipher, enqueue, next_occurrence, password_hash, query, rows, safe_path, storage, verify_password

app = FastAPI(title="CVEX Workspace", docs_url=None, redoc_url=None)
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)


@app.middleware("http")
async def response_policy(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "private, no-store")
    elif request.url.path.startswith("/assets/") and response.status_code == 200:
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    else:
        response.headers.setdefault("Cache-Control", "no-cache")
    return response


def factory():
    # Cached engine, but configuration changes are loaded by the workers.
    if not hasattr(app.state, "factory"):
        app.state.factory = make_session_factory(load_config())
    return app.state.factory


def database():
    with factory()() as db:
        yield db


def identity(request: Request, db=Depends(database, scope="function")):
    token = request.cookies.get("cvex_session", "")
    user = query(db, """SELECT u.id,u.username,u.role,s.csrf FROM cvex.web_session s
      JOIN cvex.web_user u ON u.id=s.user_id WHERE token_hash=:h AND expires_at>now()""",
      h=hashlib.sha256(token.encode()).hexdigest()).mappings().first()
    if not user:
        raise HTTPException(401, "Please sign in")
    if request.method not in {"GET", "HEAD", "OPTIONS"} and not secrets.compare_digest(request.headers.get("x-csrf-token", ""), user["csrf"]):
        raise HTTPException(403, "Invalid CSRF token")
    return dict(user)


def admin(user=Depends(identity)):
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    return user


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


class NewUser(Login):
    role: Literal["admin", "user"] = "user"


class PasswordInput(BaseModel):
    current_password: str = Field(max_length=1024)
    new_password: str = Field(min_length=12,max_length=1024)


@app.post("/api/v1/auth/password")
def change_password(body: PasswordInput, user=Depends(identity), db=Depends(database)):
    encoded=query(db,"SELECT password_hash FROM cvex.web_user WHERE id=:u",u=user["id"]).scalar()
    if not verify_password(body.current_password,encoded):
        raise HTTPException(403,"Current password is incorrect")
    query(db,"UPDATE cvex.web_user SET password_hash=:p WHERE id=:u",p=password_hash(body.new_password),u=user["id"])
    query(db,"DELETE FROM cvex.web_session WHERE user_id=:u",u=user["id"])
    audit(db,user["username"],"password_changed")
    db.commit()
    return {"ok":True}


class ProjectInput(BaseModel):
    company: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=200)


class ScheduleInput(BaseModel):
    enabled: bool = False
    mode: Literal["cron", "interval"] = "cron"
    expression: str = "0 7 * * *"
    timezone: str = "Europe/Belgrade"
    interval_seconds: int = Field(default=1800, ge=60, le=31536000)


class SettingsInput(BaseModel):
    freshness_sla: str = "2h"
    initial_retry_delay: str = "30s"
    max_retry_delay: str = "10m"
    request_timeout: str = "120s"
    no_key_request_pause: str = "10s"
    api_key_request_pause: str = "2s"
    api_key: str | None = Field(default=None, max_length=500)


@app.post("/api/v1/auth/login")
def login(body: Login, request: Request, db=Depends(database)):
    from fastapi.responses import JSONResponse
    address = request.client.host if request.client else "unknown"
    attempt = query(db, """INSERT INTO cvex.login_attempt(address,attempts) VALUES(:a,1)
      ON CONFLICT(address) DO UPDATE SET attempts=CASE WHEN cvex.login_attempt.window_start<now()-interval '10 minutes'
      THEN 1 ELSE cvex.login_attempt.attempts+1 END, window_start=CASE WHEN cvex.login_attempt.window_start<now()-interval '10 minutes'
      THEN now() ELSE cvex.login_attempt.window_start END RETURNING attempts""", a=address).scalar()
    db.commit()
    if attempt > 20:
        raise HTTPException(429, "Too many attempts. Try again in ten minutes.")
    user = query(db, "SELECT * FROM cvex.web_user WHERE username=:u", u=body.username).mappings().first()
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    query(db, "DELETE FROM cvex.web_session WHERE expires_at<now()")
    query(db, "INSERT INTO cvex.web_session VALUES(:h,:u,:c,:e)",
          h=hashlib.sha256(token.encode()).hexdigest(), u=user["id"], c=csrf, e=utcnow()+timedelta(hours=12))
    audit(db, body.username, "login")
    query(db, "DELETE FROM cvex.login_attempt WHERE address=:a", a=address)
    db.commit()
    response = JSONResponse({"username": user["username"], "role": user["role"], "csrf": csrf})
    response.set_cookie("cvex_session", token, httponly=True, secure=os.getenv("CVEX_COOKIE_SECURE", "true") == "true", samesite="strict", max_age=43200)
    return response


@app.get("/api/v1/auth/me")
def me(user=Depends(identity)):
    return user


@app.post("/api/v1/auth/logout")
def logout(request: Request, user=Depends(identity), db=Depends(database)):
    from fastapi.responses import JSONResponse
    query(db, "DELETE FROM cvex.web_session WHERE token_hash=:h", h=hashlib.sha256(request.cookies.get("cvex_session", "").encode()).hexdigest())
    db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie("cvex_session")
    return response


@app.get("/api/v1/users")
def users(user=Depends(admin), db=Depends(database)):
    return rows(db, "SELECT id,username,role,created_at FROM cvex.web_user ORDER BY username")


@app.post("/api/v1/users", status_code=201)
def create_user(body: NewUser, user=Depends(admin), db=Depends(database)):
    if query(db, "SELECT 1 FROM cvex.web_user WHERE username=:u", u=body.username).scalar():
        raise HTTPException(409, "Username already exists")
    try:
        encoded = password_hash(body.password)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    query(db, "INSERT INTO cvex.web_user(username,password_hash,role) VALUES(:u,:p,:r)", u=body.username, p=encoded, r=body.role)
    audit(db, user["username"], "user_created", username=body.username, role=body.role)
    db.commit()
    return {"ok": True}


@app.get("/api/v1/projects")
def projects(user=Depends(identity), db=Depends(database)):
    return rows(db, """SELECT p.*,v.label active_version,v.filename,s.enabled schedule_enabled,s.next_run,
      j.state latest_state,j.finished_at latest_finished,j.summary latest_summary
      FROM cvex.project p LEFT JOIN cvex.project_version v ON v.id=p.active_version_id
      LEFT JOIN cvex.web_schedule s ON s.target='project:'||p.id::text
      LEFT JOIN LATERAL (SELECT state,finished_at,summary FROM cvex.report_job WHERE project_id=p.id ORDER BY created_at DESC LIMIT 1) j ON true
      ORDER BY p.created_at DESC""")


@app.post("/api/v1/projects", status_code=201)
def create_project(body: ProjectInput, user=Depends(identity), db=Depends(database)):
    if not body.company.strip() or not body.name.strip():
        raise HTTPException(422, "Company and project name are required")
    pid = query(db, "INSERT INTO cvex.project(company,name) VALUES(:c,:n) RETURNING id", c=body.company.strip(), n=body.name.strip()).scalar()
    query(db, "INSERT INTO cvex.web_schedule(target) VALUES(:t)", t=f"project:{pid}")
    audit(db, user["username"], "project_created", project_id=pid)
    db.commit()
    return {"id": pid}


@app.get("/api/v1/projects/{project_id}")
def project_detail(project_id: UUID, user=Depends(identity), db=Depends(database)):
    result = query(db, "SELECT * FROM cvex.project WHERE id=:id", id=project_id).mappings().first()
    if not result:
        raise HTTPException(404, "Project not found")
    return {**result, "versions": rows(db, "SELECT * FROM cvex.project_version WHERE project_id=:id ORDER BY created_at DESC", id=project_id),
            "jobs": rows(db, """WITH visible AS (
            (SELECT * FROM cvex.report_job WHERE project_id=:id AND state IN ('succeeded','partial') ORDER BY created_at DESC LIMIT 30)
            UNION ALL
            (SELECT * FROM cvex.report_job WHERE project_id=:id AND state NOT IN ('succeeded','partial','expired') ORDER BY created_at DESC LIMIT 70)
            ) SELECT j.id,j.version_id,j.state,j.trigger,j.scheduled_at,j.created_at,j.started_at,j.finished_at,
            j.progress,j.total,j.summary,j.error,j.artifacts,v.label version_label
            FROM visible j JOIN cvex.project_version v ON v.id=j.version_id
            ORDER BY j.created_at DESC""", id=project_id)}


@app.post("/api/v1/projects/{project_id}/versions", status_code=201)
def upload(project_id: UUID, label: str = "", make_active: bool = False, file: UploadFile = File(...), user=Depends(identity), db=Depends(database)):
    project = query(db, "SELECT * FROM cvex.project WHERE id=:p FOR UPDATE", p=project_id).mappings().first()
    if not project:
        raise HTTPException(404, "Project not found")
    version_id = uuid4()
    path = safe_path(f"projects/{project_id}/uploads/{version_id}.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    size = 0
    try:
        with path.open("xb") as output:
            while chunk := file.file.read(1024*1024):
                size += len(chunk)
                if size > int(os.getenv("CVEX_UPLOAD_LIMIT_BYTES", str(100*1024*1024))):
                    raise HTTPException(413, "SBOM exceeds upload size limit")
                output.write(chunk)
        try:
            payload = json.loads(path.read_bytes())
            validate_spdx(payload)
        except (ValueError, UnicodeError) as exc:
            raise HTTPException(422, str(exc))
        sbom_id, count = import_spdx(db, path, project["company"], project["name"], label or file.filename or "upload", commit=False)
        existing = query(db, "SELECT id FROM cvex.project_version WHERE project_id=:p AND sbom_id=:s", p=project_id, s=sbom_id).scalar()
        if existing:
            path.unlink(missing_ok=True)
            version_id = existing
        else:
            query(db, """INSERT INTO cvex.project_version(id,project_id,sbom_id,label,filename,upload_path)
              VALUES(:id,:p,:s,:l,:f,:path)""", id=version_id, p=project_id, s=sbom_id,
              l=(label or file.filename or "SBOM")[:200], f=Path(file.filename or "sbom.json").name[:255], path=str(path.relative_to(storage())))
        query(db, "UPDATE cvex.project SET active_version_id=:v WHERE id=:p AND (active_version_id IS NULL OR :active)", v=version_id, p=project_id, active=make_active)
        audit(db, user["username"], "sbom_uploaded", project_id=project_id, version_id=version_id)
        db.commit()
        return {"id": version_id, "sbom_id": sbom_id, "components": count}
    except Exception:
        db.rollback()
        path.unlink(missing_ok=True)
        raise


@app.post("/api/v1/projects/{project_id}/versions/{version_id}/activate")
def activate(project_id: UUID, version_id: UUID, user=Depends(identity), db=Depends(database)):
    result = query(db, """UPDATE cvex.project SET active_version_id=:v WHERE id=:p
      AND EXISTS(SELECT 1 FROM cvex.project_version WHERE id=:v AND project_id=:p)""", p=project_id, v=version_id)
    if not result.rowcount:
        raise HTTPException(404, "Version not found in project")
    audit(db, user["username"], "version_activated", project_id=project_id, version_id=version_id)
    db.commit()
    return {"ok": True}


@app.post("/api/v1/projects/{project_id}/runs", status_code=202)
def run_now(project_id: UUID, user=Depends(identity), db=Depends(database)):
    try:
        jid = enqueue(db, project_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    audit(db, user["username"], "report_requested", project_id=project_id, job_id=jid)
    db.commit()
    return {"id": jid}


@app.get("/api/v1/runs/{job_id}/artifacts/{kind}")
def artifact(job_id: UUID, kind: str, download: bool = False, user=Depends(identity), db=Depends(database, scope="function")):
    record = query(db, "SELECT artifacts FROM cvex.report_job WHERE id=:id AND state IN ('succeeded','partial')", id=job_id).scalar()
    if not record or kind not in record:
        raise HTTPException(404, "Report artifact not available")
    path = safe_path(record[kind])
    if not path.is_file():
        raise HTTPException(404, "Report artifact not available")
    response = FileResponse(path, filename=path.name, content_disposition_type="attachment" if download or kind != "html" else "inline")
    response.headers["Content-Security-Policy"] = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"
    return response


def validate_target(db, target):
    if target in {"nvd", "cve"}:
        return
    try:
        pid = UUID(target.removeprefix("project:"))
    except ValueError:
        raise HTTPException(404, "Unknown schedule")
    if not target.startswith("project:") or not query(db, "SELECT 1 FROM cvex.project WHERE id=:p", p=pid).scalar():
        raise HTTPException(404, "Unknown project")


@app.get("/api/v1/schedules/{target}")
def schedule(target: str, user=Depends(admin), db=Depends(database)):
    validate_target(db, target)
    value = query(db, "SELECT * FROM cvex.web_schedule WHERE target=:t", t=target).mappings().first()
    result = dict(value) if value else {"target": target, **ScheduleInput().model_dump()}
    upcoming, after = [], utcnow()
    for _ in range(5):
        after = next_occurrence(result, after)
        upcoming.append(after)
    return {**result, "upcoming": upcoming}


@app.put("/api/v1/schedules/{target}")
def save_schedule(target: str, body: ScheduleInput, user=Depends(admin), db=Depends(database)):
    validate_target(db, target)
    if target.startswith("project:") and body.mode != "cron":
        raise HTTPException(422, "Projects use cron schedules")
    try:
        ZoneInfo(body.timezone)
        if len(body.expression.split()) != 5 or not croniter.is_valid(body.expression):
            raise ValueError("Use a valid five-field cron expression")
        next_run = next_occurrence(body.model_dump()) if body.enabled else None
    except (ValueError, ZoneInfoNotFoundError) as exc:
        raise HTTPException(422, str(exc))
    query(db, """INSERT INTO cvex.web_schedule(target,enabled,mode,expression,timezone,interval_seconds,next_run)
      VALUES(:t,:enabled,:mode,:expression,:timezone,:interval_seconds,:n) ON CONFLICT(target) DO UPDATE SET
      enabled=:enabled,mode=:mode,expression=:expression,timezone=:timezone,interval_seconds=:interval_seconds,next_run=:n,
      version=cvex.web_schedule.version+1""", t=target, n=next_run, **body.model_dump())
    audit(db, user["username"], "schedule_updated", target=target, **body.model_dump())
    db.commit()
    return schedule(target, user, db)


@app.get("/api/v1/settings/{source}")
def settings(source: Literal["cve", "nvd"], user=Depends(admin), db=Depends(database)):
    value = query(db, "SELECT * FROM cvex.worker_setting WHERE source=:s", s=source).mappings().first()
    base = load_config().sources[source].model_dump()
    permitted = {k: base.get(k) for k in SettingsInput.model_fields if k != "api_key"}
    return {"source": source, "settings": {**permitted, **(value["settings"] if value else {})},
            "version": value["version"] if value else 0, "has_api_key": bool(value["encrypted_key"] if value and value["encrypted_key"] is not None else base.get("api_key"))}


@app.put("/api/v1/settings/{source}")
def save_settings(source: Literal["cve", "nvd"], body: SettingsInput, user=Depends(admin), db=Depends(database)):
    from cvex.util import duration_seconds
    values = body.model_dump(exclude={"api_key"})
    try:
        for value in values.values():
            if not 1 <= duration_seconds(value) <= 86400:
                raise ValueError("Durations must be between 1 second and 24 hours")
        if duration_seconds(body.max_retry_delay) < duration_seconds(body.initial_retry_delay):
            raise ValueError("Maximum retry delay must be at least the initial delay")
        encrypted = (cipher().encrypt(body.api_key.encode()).decode() if body.api_key else "") if body.api_key is not None else None
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    query(db, """INSERT INTO cvex.worker_setting(source,settings,encrypted_key) VALUES(:s,CAST(:v AS jsonb),:k)
      ON CONFLICT(source) DO UPDATE SET settings=CAST(:v AS jsonb),encrypted_key=COALESCE(:k,cvex.worker_setting.encrypted_key),version=cvex.worker_setting.version+1""",
      s=source, v=json.dumps(values), k=encrypted)
    audit(db, user["username"], "worker_settings_updated", source=source, credential_changed=body.api_key is not None)
    db.commit()
    return settings(source, user, db)


def status_payload(db):
    root = storage()
    usage = shutil.disk_usage(root if root.exists() else root.parent)
    return {"workers": rows(db, "SELECT *,CASE WHEN name='storage' THEN heartbeat_at<now()-interval '90 seconds' ELSE heartbeat_at<now()-interval '15 seconds' END stale FROM cvex.worker_telemetry ORDER BY name"),
            "recent_syncs": rows(db, """SELECT id,source,status,started_at,finished_at,
              extract(epoch FROM finished_at-started_at) duration_seconds,
              details->>'records_seen' processed,details->>'records_changed' changed
              FROM cvex.source_run WHERE source IN ('nvd','cve') ORDER BY started_at DESC LIMIT 12"""),
            "sources": rows(db, "SELECT source,status,health,last_success,last_attempt,error_count,next_retry_at,CASE WHEN last_error IS NOT NULL THEN split_part(last_error, ':', 1) END error_type FROM cvex.connector_state ORDER BY source"),
            "schedules": rows(db, "SELECT target,enabled,next_run,version FROM cvex.web_schedule ORDER BY target"),
            "queue": rows(db, "SELECT state,count(*) count,min(created_at) oldest FROM cvex.report_job WHERE state IN ('queued','scanning','exporting') GROUP BY state"),
            "jobs": rows(db,"""SELECT j.id,j.state,j.created_at,j.started_at,j.progress,j.total,p.company,p.name
              FROM cvex.report_job j JOIN cvex.project p ON p.id=j.project_id WHERE j.state IN ('queued','scanning','exporting') ORDER BY j.created_at LIMIT 30"""),
            "database_bytes": query(db, "SELECT pg_database_size(current_database())").scalar(),
            "disk_free_bytes": usage.free, "disk_total_bytes": usage.total, "server_time": utcnow()}


@app.get("/api/v1/admin/status")
def status(user=Depends(admin), db=Depends(database)):
    return status_payload(db)


@app.get("/api/v1/activity")
def activity(user=Depends(identity), db=Depends(database)):
    return rows(db, "SELECT * FROM cvex.web_audit ORDER BY id DESC LIMIT 100")


@app.get("/api/v1/admin/events")
async def events(request: Request, user=Depends(admin)):
    token_hash = hashlib.sha256(request.cookies.get("cvex_session", "").encode()).hexdigest()
    def sample():
        with factory()() as db:
            if not query(db, "SELECT 1 FROM cvex.web_session WHERE token_hash=:h AND expires_at>now()", h=token_hash).scalar():
                return None
            return status_payload(db)
    async def stream():
        while not await request.is_disconnected():
            result = await asyncio.to_thread(sample)
            if result is None:
                return
            yield "data: " + json.dumps(jsonable_encoder(result)) + "\n\n"
            await asyncio.sleep(3)
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/v1/health")
def health():
    return {"status": "ok"}


frontend = Path(os.getenv("CVEX_FRONTEND_DIST", "frontend/dist"))
if frontend.is_dir():
    app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")
