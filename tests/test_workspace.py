import json
import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from cvex.workspace import next_occurrence, password_hash, safe_path, verify_password


def test_passwords_are_salted_and_verified():
    one = password_hash("a sufficiently long password")
    two = password_hash("a sufficiently long password")
    assert one != two
    assert verify_password("a sufficiently long password", one)
    assert not verify_password("incorrect password", one)
    with pytest.raises(ValueError):
        password_hash("short")


def test_schedule_dst_gap_fold_and_timezone():
    schedule = {"mode": "cron", "expression": "30 2 * * *", "timezone": "Europe/Belgrade"}
    before_gap = datetime(2026, 3, 28, 2, tzinfo=timezone.utc)
    assert next_occurrence(schedule, before_gap) == datetime(2026, 3, 30, 0, 30, tzinfo=timezone.utc)
    before_fold = datetime(2026, 10, 24, 3, tzinfo=timezone.utc)
    first = next_occurrence(schedule, before_fold)
    assert first == datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
    assert next_occurrence(schedule, first) == datetime(2026, 10, 26, 1, 30, tzinfo=timezone.utc)


def test_storage_cannot_escape_root(tmp_path, monkeypatch):
    monkeypatch.setenv("CVEX_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValueError):
        safe_path("../secret")
    with pytest.raises(ValueError):
        safe_path(".")
    (tmp_path / "escape").symlink_to(tmp_path.parent, target_is_directory=True)
    with pytest.raises(ValueError):
        safe_path("escape/secret")


@pytest.mark.skipif(not os.getenv("CVEX_TEST_DATABASE_URL"), reason="requires migrated disposable PostgreSQL")
def test_workspace_api_execution_and_retention(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from cvex.web import app
    from cvex.config import load_config
    from cvex.db.session import make_session_factory
    from cvex.jobs import report_tick, cleanup_reports, scheduler_tick
    from cvex.workspace import query
    monkeypatch.setenv("CVEX_DATABASE_URL", os.environ["CVEX_TEST_DATABASE_URL"])
    monkeypatch.setenv("CVEX_COOKIE_SECURE", "false")
    monkeypatch.setenv("CVEX_WORKSPACE_ROOT", str(tmp_path))
    config = load_config()
    factory = make_session_factory(config)
    app.state.factory = factory
    username = "admin-"+uuid4().hex[:8]
    with factory() as db:
        # Keep jobs from earlier disposable-test invocations out of this test's queue.
        query(db,"UPDATE cvex.report_job SET available_at=now()+interval '1 day' WHERE state='queued'")
        query(db, "INSERT INTO cvex.web_user(username,password_hash,role) VALUES(:u,:p,'admin')", u=username, p=password_hash("workspace test password"))
        db.commit()
    client = TestClient(app)
    assert client.get("/api/v1/projects").status_code == 401
    response = client.post("/api/v1/auth/login", json={"username":username,"password":"workspace test password"})
    assert response.status_code == 200, response.text
    assert client.post("/api/v1/projects", json={"company":"Acme","name":"test"}).status_code == 403
    client.headers["X-CSRF-Token"] = response.json()["csrf"]
    pid = client.post("/api/v1/projects", json={"company":"Acme","name":"test"}).json()["id"]
    invalid = client.post(f"/api/v1/projects/{pid}/versions", files={"file":("invalid.json",b'{}','application/json')})
    assert invalid.status_code == 422
    payload = {"spdxVersion":"SPDX-2.3","name":uuid4().hex,"packages":[{"SPDXID":"SPDXRef-curl","name":"curl","versionInfo":"8.0.1"}]}
    uploaded = client.post(f"/api/v1/projects/{pid}/versions?label=1.0",files={"file":("sbom.json",json.dumps(payload),'application/json')})
    assert uploaded.status_code == 201, uploaded.text
    version = uploaded.json()["id"]
    second = client.post(f"/api/v1/projects/{pid}/versions",files={"file":("again.json",json.dumps(payload),'application/json')})
    assert second.json()["id"] == version
    jid = client.post(f"/api/v1/projects/{pid}/runs").json()["id"]
    assert client.post(f"/api/v1/projects/{pid}/runs").json()["id"] == jid
    import cvex.jobs as jobs
    # A retried scan must not display the previous attempt's percentage.
    with factory() as db:
        query(db, "UPDATE cvex.report_job SET progress=99,total=100 WHERE id=:id", id=jid)
        db.commit()
    original_match = jobs.run_match
    def checked_match(db, *args, **kwargs):
        with factory() as observer:
            current = query(observer, "SELECT progress,total FROM cvex.report_job WHERE state='scanning'").mappings().one()
            assert current["progress"] == 0 and current["total"] is None
        return original_match(db, *args, **kwargs)
    monkeypatch.setattr(jobs, "run_match", checked_match)
    render = jobs._render_findings_html
    def broken_export(_payload):
        raise OSError("simulated interrupted export")
    monkeypatch.setattr(jobs, "_render_findings_html", broken_export)
    report_tick(factory, config)
    with factory() as db:
        interrupted=query(db,"SELECT * FROM cvex.report_job WHERE id=:id",id=jid).mappings().one()
        assert interrupted["state"]=="queued"
        assert query(db,"SELECT payload FROM cvex.report_snapshot WHERE job_id=:id",id=jid).scalar() is not None
        original_scan=interrupted["scan_id"]
        query(db,"UPDATE cvex.report_job SET available_at=now() WHERE id=:id",id=jid)
        db.commit()
    monkeypatch.setattr(jobs, "_render_findings_html", render)
    report_tick(factory, config)
    with factory() as db:
        job = query(db, "SELECT * FROM cvex.report_job WHERE id=:id", id=jid).mappings().one()
        assert job["state"] == "succeeded", job["error"]
        assert job["scan_id"] == original_scan and job["attempts"] == 2
    html = client.get(f"/api/v1/runs/{jid}/artifacts/html")
    assert html.status_code == 200 and "inline" in html.headers["content-disposition"]
    assert "sandbox" in html.headers["content-security-policy"]
    downloaded = client.get(f"/api/v1/runs/{jid}/artifacts/html?download=true")
    assert "attachment" in downloaded.headers["content-disposition"]
    assert client.get(f"/api/v1/runs/{jid}/artifacts/unknown").status_code == 404
    schedule = {"enabled":True,"mode":"cron","expression":"0 7 * * *","timezone":"Europe/Belgrade","interval_seconds":1800}
    saved = client.put(f"/api/v1/schedules/project:{pid}",json=schedule)
    assert saved.status_code == 200 and len(saved.json()["upcoming"]) == 5
    from cryptography.fernet import Fernet
    monkeypatch.setenv("CVEX_ENCRYPTION_KEY",Fernet.generate_key().decode())
    secret="test-key-never-return-this"
    key_result=client.put('/api/v1/settings/nvd',json={"api_key":secret})
    assert key_result.status_code==200 and secret not in key_result.text
    assert key_result.json()["has_api_key"] is True
    with factory() as db:
        assert secret not in query(db,"SELECT encrypted_key FROM cvex.worker_setting WHERE source='nvd'").scalar()
    cleared=client.put('/api/v1/settings/nvd',json={"api_key":""})
    assert cleared.status_code==200 and cleared.json()["has_api_key"] is False
    with factory() as db:
        query(db, "UPDATE cvex.web_schedule SET next_run=now()-interval '3 days' WHERE target=:t",t="project:"+pid)
        db.commit()
    scheduler_tick(factory)
    scheduler_tick(factory)
    with factory() as db:
        assert query(db,"SELECT count(*) FROM cvex.report_job WHERE project_id=:p AND trigger='scheduled'",p=pid).scalar()==1
        # Older successful report sets expire; queued/failed jobs do not count.
        query(db,"UPDATE cvex.report_job SET finished_at=now()-interval '1 year' WHERE id=:id",id=jid)
        for i in range(30):
            query(db,"INSERT INTO cvex.report_job(project_id,version_id,trigger,state,finished_at) VALUES(:p,:v,'manual','succeeded',now())",p=pid,v=version)
        db.commit()
    original_query = jobs.query
    def fail_cleanup(db, sql, **params):
        if "DELETE FROM cvex.report_snapshot" in sql:
            raise RuntimeError("simulated cleanup rollback")
        return original_query(db, sql, **params)
    monkeypatch.setattr(jobs, "query", fail_cleanup)
    with pytest.raises(RuntimeError, match="cleanup rollback"):
        cleanup_reports(factory)
    assert client.get(f"/api/v1/runs/{jid}/artifacts/html").status_code == 200
    monkeypatch.setattr(jobs, "query", original_query)
    original_rmtree = jobs.shutil.rmtree
    def fail_delete(*args, **kwargs):
        raise OSError("simulated unavailable filesystem")
    monkeypatch.setattr(jobs.shutil, "rmtree", fail_delete)
    cleanup_reports(factory)
    with factory() as db:
        assert query(db, "SELECT count(*) FROM cvex.artifact_cleanup").scalar() > 0
    monkeypatch.setattr(jobs.shutil, "rmtree", original_rmtree)
    cleanup_reports(factory)
    with factory() as db:
        assert query(db, "SELECT count(*) FROM cvex.artifact_cleanup").scalar() == 0
    assert client.get(f"/api/v1/runs/{jid}/artifacts/html").status_code==404
    assert client.get(f"/api/v1/projects/{pid}").json()["versions"]
    with factory() as db:
        query(db, "UPDATE cvex.report_job SET state='failed' WHERE project_id=:p AND state='queued'", p=pid)
        db.commit()
    failed_id = client.post(f"/api/v1/projects/{pid}/runs").json()["id"]
    monkeypatch.setattr(jobs, "_render_findings_html", broken_export)
    for attempt in range(3):
        with factory() as db:
            query(db, "UPDATE cvex.report_job SET available_at=now() WHERE id=:id", id=failed_id)
            db.commit()
        report_tick(factory, config)
    monkeypatch.setattr(jobs, "_render_findings_html", render)
    with factory() as db:
        failed = query(db, "SELECT * FROM cvex.report_job WHERE id=:id", id=failed_id).mappings().one()
        assert failed["state"] == "failed" and failed["scan_id"] is None and failed["finished_at"] is not None
        assert query(db, "SELECT count(*) FROM cvex.report_snapshot WHERE job_id=:id", id=failed_id).scalar() == 0
    assert not (tmp_path / f"projects/{pid}/reports/{failed_id}.pending").exists()
    # Partial scans remain downloadable and visibly disclose incomplete assessment.
    import cvex.matcher as matcher
    def broken_component(*args):
        raise ValueError("simulated component failure")
    monkeypatch.setattr(matcher, "_match_component", broken_component)
    partial_id = client.post(f"/api/v1/projects/{pid}/runs").json()["id"]
    report_tick(factory, config)
    with factory() as db:
        assert query(db, "SELECT state FROM cvex.report_job WHERE id=:id", id=partial_id).scalar() == "partial"
        assert query(db, "SELECT count(*) FROM cvex.report_snapshot WHERE job_id=:id", id=partial_id).scalar() == 1
    partial_html = client.get(f"/api/v1/runs/{partial_id}/artifacts/html")
    assert partial_html.status_code == 200 and "Partial scan" in partial_html.text
    # Ordinary internal users may operate projects but not change schedules or keys.
    ordinary="user-"+uuid4().hex[:8]
    assert client.post('/api/v1/users',json={"username":ordinary,"password":"workspace test password","role":"user"}).status_code==201
    client.post('/api/v1/auth/logout')
    response=client.post('/api/v1/auth/login',json={"username":ordinary,"password":"workspace test password"})
    client.headers['X-CSRF-Token']=response.json()['csrf']
    assert client.get('/api/v1/projects').status_code==200
    assert client.put(f'/api/v1/schedules/project:{pid}',json=schedule).status_code==403
    assert client.get('/api/v1/settings/nvd').status_code==403
