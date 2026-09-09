"""Deletion is admin-only, transaction-safe and isolated to one workspace."""
import json
import os
from uuid import UUID, uuid4

import pytest

from cvex.workspace import password_hash, query

pytestmark = pytest.mark.skipif(not os.getenv("CVEX_TEST_DATABASE_URL"), reason="requires disposable PostgreSQL")


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from cvex.config import load_config
    from cvex.db.session import make_session_factory
    from cvex.web import app
    from cvex.projects import delete_project
    from cvex.jobs import drain_artifact_cleanup

    monkeypatch.setenv("CVEX_DATABASE_URL", os.environ["CVEX_TEST_DATABASE_URL"])
    monkeypatch.setenv("CVEX_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("CVEX_COOKIE_SECURE", "false")
    factory = make_session_factory(load_config())
    monkeypatch.setattr(app.state, "factory", factory, raising=False)
    accounts = {role: role + uuid4().hex for role in ("admin", "user")}
    with factory() as db:
        for role, username in accounts.items():
            query(db, "INSERT INTO cvex.web_user(username,password_hash,role) VALUES(:u,:p,:r)",
                  u=username, p=password_hash("project deletion test password"), r=role)
        db.commit()
    clients = {}
    for role, username in accounts.items():
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/auth/login", json={"username": username, "password": "project deletion test password"})
        assert response.status_code == 200
        client.headers["X-CSRF-Token"] = response.json()["csrf"]
        clients[role] = client
    admin = clients["admin"]
    projects = []
    payload = {"spdxVersion": "SPDX-2.3", "name": uuid4().hex,
               "packages": [{"SPDXID": "p", "name": "delete-test-component", "versionInfo": "1.0"}]}
    for name in ("Delete me", "Keep me"):
        pid = admin.post("/api/v1/projects", json={"company": "Test", "name": name}).json()["id"]
        uploaded = admin.post(f"/api/v1/projects/{pid}/versions", files={"file": ("sbom.json", json.dumps(payload), "application/json")})
        assert uploaded.status_code == 201
        projects.append({"id": pid, **{"version": uploaded.json()["id"], "sbom": uploaded.json()["sbom_id"]}})
    try:
        yield factory, clients, projects, tmp_path
    finally:
        with factory() as db:
            for project in projects:
                if query(db, "SELECT 1 FROM cvex.project WHERE id=:p", p=UUID(project["id"])).scalar():
                    query(db, "UPDATE cvex.report_job SET state='failed' WHERE project_id=:p", p=UUID(project["id"]))
                    delete_project(db, UUID(project["id"]), "test-cleanup")
            db.commit()
        drain_artifact_cleanup(factory)
        for client in clients.values():
            client.close()
        factory.kw["bind"].dispose()


def add_report(factory, project, root, *, state="succeeded", snapshot_only=False):
    pid, vid, sbom = (UUID(project[key]) for key in ("id", "version", "sbom"))
    with factory() as db:
        sid = query(db, "INSERT INTO cvex.scan(sbom_document_id,status) VALUES(:s,'completed') RETURNING id", s=sbom).scalar()
        job = query(db, """INSERT INTO cvex.report_job(project_id,version_id,trigger,state,scan_id)
          VALUES(:p,:v,'manual',:state,:s) RETURNING id""", p=pid, v=vid, state=state, s=None if snapshot_only else sid).scalar()
        query(db, "INSERT INTO cvex.report_snapshot(job_id,scan_id,payload) VALUES(:j,:s,'{}')", j=job, s=sid)
        component = query(db, "SELECT id FROM cvex.sbom_component WHERE sbom_document_id=:s LIMIT 1", s=sbom).scalar()
        cve = "CVE-2099-" + str(int(uuid4().hex[:12], 16))
        vulnerability = query(db, "INSERT INTO cvex.vulnerability(cve_id) VALUES(:c) RETURNING id", c=cve).scalar()
        payload = query(db, "INSERT INTO cvex.source_payload(source,cve_id,sha256,payload) VALUES('nvd',:c,'test','{}') RETURNING id", c=cve).scalar()
        finding = query(db, """INSERT INTO cvex.vulnerability_finding(scan_id,component_id,vulnerability_id,status,confidence)
          VALUES(:s,:c,:v,'active','high') RETURNING id""", s=sid, c=component, v=vulnerability).scalar()
        query(db, """INSERT INTO cvex.finding_evidence(finding_id,source,match_type,confidence,reason,source_payload_id)
          VALUES(:f,'nvd','cpe','high','test',:p)""", f=finding, p=payload)
        query(db, """INSERT INTO cvex.scan_component_result(scan_id,component_id,status,reason_code,reason_message)
          VALUES(:s,:c,'matched','test','test')""", s=sid, c=component)
        query(db, "INSERT INTO cvex.report_export(scan_id,export_type,path,sha256) VALUES(:s,'html','test','test')", s=sid)
        relative = f"projects/{pid}/reports/{job}"
        query(db, "UPDATE cvex.report_job SET artifacts=CAST(:a AS jsonb) WHERE id=:j", j=job, a=json.dumps({"html": relative + "/findings.html"}))
        db.commit()
    directory = root / relative
    directory.mkdir(parents=True)
    (directory / "findings.html").write_text("<html>Test report</html>")
    return job, sid, finding, payload


def test_delete_removes_all_owned_reports_and_preserves_other_project(workspace):
    factory, clients, projects, root = workspace
    target, other = projects
    reports = [add_report(factory, target, root), add_report(factory, target, root, state="queued", snapshot_only=True)]
    kept = add_report(factory, other, root)
    admin = clients["admin"]
    response = admin.delete(f"/api/v1/projects/{target['id']}")
    assert response.status_code == 200, response.text
    assert response.json() == {"ok": True, "cleanup_pending": False}
    assert not (root / "projects" / target["id"]).exists()
    assert (root / "projects" / other["id"]).is_dir()
    assert admin.get(f"/api/v1/projects/{target['id']}").status_code == 404
    assert admin.delete(f"/api/v1/projects/{target['id']}").status_code == 404
    assert admin.get(f"/api/v1/runs/{kept[0]}/artifacts/html").status_code == 200
    assert admin.get(f"/api/v1/projects/{other['id']}").json()["versions"]
    with factory() as db:
        for job, scan, finding, payload in reports:
            assert admin.get(f"/api/v1/runs/{job}/artifacts/html").status_code == 404
            for table, column, value in (("report_job", "id", job), ("report_snapshot", "job_id", job),
                                          ("scan", "id", scan), ("scan_component_result", "scan_id", scan),
                                          ("report_export", "scan_id", scan), ("vulnerability_finding", "id", finding),
                                          ("finding_evidence", "finding_id", finding)):
                assert query(db, f"SELECT count(*) FROM cvex.{table} WHERE {column}=:id", id=value).scalar() == 0
            assert query(db, "SELECT 1 FROM cvex.source_payload WHERE id=:p", p=payload).scalar()
        assert query(db, "SELECT 1 FROM cvex.sbom_document WHERE id=:s", s=UUID(target["sbom"])).scalar()
        assert not query(db, "SELECT 1 FROM cvex.web_schedule WHERE target=:t", t="project:" + target["id"]).scalar()
        assert query(db, "SELECT count(*) FROM cvex.web_audit WHERE action='project_deleted' AND details->>'project_id'=:p", p=target["id"]).scalar() == 1
    assert admin.put(f"/api/v1/schedules/project:{target['id']}", json={}).status_code == 404


def test_delete_requires_admin_and_csrf(workspace):
    from fastapi.testclient import TestClient
    from cvex.web import app
    _, clients, projects, root = workspace
    path = f"/api/v1/projects/{projects[0]['id']}"
    with TestClient(app) as anonymous:
        assert anonymous.delete(path).status_code == 401
    assert clients["user"].delete(path).status_code == 403
    assert clients["admin"].delete(path, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert clients["admin"].get(path).status_code == 200
    assert (root / "projects" / projects[0]["id"]).is_dir()


@pytest.mark.parametrize("state", ["scanning", "exporting"])
def test_delete_refuses_active_reports(workspace, state):
    factory, clients, projects, root = workspace
    add_report(factory, projects[0], root, state=state)
    response = clients["admin"].delete(f"/api/v1/projects/{projects[0]['id']}")
    assert response.status_code == 409
    assert "running" in response.json()["detail"]
    assert (root / "projects" / projects[0]["id"]).exists()
    with factory() as db:
        assert not query(db, "SELECT 1 FROM cvex.artifact_cleanup WHERE path=:p", p="projects/" + projects[0]["id"]).scalar()


def test_failed_transaction_preserves_project_and_files(workspace, monkeypatch):
    import cvex.projects as deletion
    factory, clients, projects, root = workspace
    report = add_report(factory, projects[0], root)
    with monkeypatch.context() as patch:
        def fail(*args, **kwargs):
            raise RuntimeError("simulated audit failure")
        patch.setattr(deletion, "audit", fail)
        assert clients["admin"].delete(f"/api/v1/projects/{projects[0]['id']}").status_code == 500
    assert clients["admin"].get(f"/api/v1/runs/{report[0]}/artifacts/html").status_code == 200
    assert (root / "projects" / projects[0]["id"]).exists()
    with factory() as db:
        assert not query(db, "SELECT 1 FROM cvex.artifact_cleanup WHERE path=:p", p="projects/" + projects[0]["id"]).scalar()


def test_file_failure_is_durable_and_retried(workspace, monkeypatch):
    import cvex.jobs as jobs
    factory, clients, projects, root = workspace
    with monkeypatch.context() as patch:
        def fail(*args, **kwargs):
            raise OSError("simulated read-only disk")
        patch.setattr(jobs.shutil, "rmtree", fail)
        response = clients["admin"].delete(f"/api/v1/projects/{projects[0]['id']}")
        assert response.status_code == 200
        assert response.json()["cleanup_pending"] is True
    assert (root / "projects" / projects[0]["id"]).exists()
    jobs.drain_artifact_cleanup(factory)
    assert not (root / "projects" / projects[0]["id"]).exists()
    assert (root / "projects" / projects[1]["id"]).exists()


def test_cleanup_never_follows_a_project_symlink(workspace):
    from cvex.jobs import drain_artifact_cleanup
    factory, _, projects, root = workspace
    link = root / "projects" / str(uuid4())
    link.symlink_to(root / "projects" / projects[1]["id"], target_is_directory=True)
    with factory() as db:
        query(db, "INSERT INTO cvex.artifact_cleanup(path) VALUES(:p)", p=str(link.relative_to(root)))
        db.commit()
    assert drain_artifact_cleanup(factory, str(link.relative_to(root))) is True
    assert (root / "projects" / projects[1]["id"]).exists()
    link.unlink()
    drain_artifact_cleanup(factory)


def test_concurrent_schedule_and_enqueue_cannot_resurrect_deleted_project(workspace):
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    from cvex.projects import delete_project
    factory, clients, projects, _ = workspace
    pid = projects[0]["id"]
    # Hold deletion open while two other requests try to mutate the same project.
    with ThreadPoolExecutor(max_workers=2) as pool:
        with factory() as db:
            delete_project(db, UUID(pid), "test-admin")
            schedule = pool.submit(clients["admin"].put, f"/api/v1/schedules/project:{pid}", json={})
            enqueue = pool.submit(clients["admin"].post, f"/api/v1/projects/{pid}/runs")
            try:
                for request in (schedule, enqueue):
                    with pytest.raises(TimeoutError):
                        request.result(timeout=0.2)
            finally:
                db.commit()
        assert schedule.result(timeout=5).status_code == 404
        assert enqueue.result(timeout=5).status_code == 422
    with factory() as db:
        assert not query(db, "SELECT 1 FROM cvex.web_schedule WHERE target=:t", t="project:" + pid).scalar()
        assert not query(db, "SELECT 1 FROM cvex.report_job WHERE project_id=:p", p=UUID(pid)).scalar()


def test_delete_one_report_preserves_project_sbom_schedule_and_other_reports(workspace):
    factory, clients, projects, root = workspace
    target, other = projects
    removed = add_report(factory, target, root)
    kept = add_report(factory, target, root)
    foreign = add_report(factory, other, root)
    admin = clients["admin"]
    path = f"/api/v1/projects/{target['id']}/runs/{removed[0]}"
    pending = root / f"projects/{target['id']}/reports/{removed[0]}.pending"
    pending.mkdir()
    response = admin.delete(path)
    assert response.status_code == 200, response.text
    assert response.json()["cleanup_pending"] is False
    assert not pending.exists()
    assert not (root / f"projects/{target['id']}/reports/{removed[0]}").exists()
    assert admin.get(f"/api/v1/runs/{removed[0]}/artifacts/html").status_code == 404
    for report in (kept, foreign):
        assert admin.get(f"/api/v1/runs/{report[0]}/artifacts/html").status_code == 200
    assert admin.get(f"/api/v1/projects/{target['id']}").json()["versions"]
    assert admin.get(f"/api/v1/schedules/project:{target['id']}").status_code == 200
    assert admin.delete(path).status_code == 404
    with factory() as db:
        for table, column, value in (("scan", "id", removed[1]), ("report_snapshot", "job_id", removed[0]),
                                     ("report_export", "scan_id", removed[1]), ("scan_component_result", "scan_id", removed[1]),
                                     ("vulnerability_finding", "id", removed[2]), ("finding_evidence", "finding_id", removed[2])):
            assert not query(db, f"SELECT 1 FROM cvex.{table} WHERE {column}=:id", id=value).scalar()
        assert query(db, "SELECT 1 FROM cvex.source_payload WHERE id=:p", p=removed[3]).scalar()
        assert query(db, "SELECT count(*) FROM cvex.web_audit WHERE action='report_deleted' AND details->>'job_id'=:j", j=str(removed[0])).scalar() == 1


def test_report_deletion_requires_admin_csrf_and_correct_project(workspace):
    from fastapi.testclient import TestClient
    from cvex.web import app
    factory, clients, projects, root = workspace
    report = add_report(factory, projects[0], root)
    path = f"/api/v1/projects/{projects[0]['id']}/runs/{report[0]}"
    with TestClient(app) as anonymous:
        assert anonymous.delete(path).status_code == 401
    assert clients["user"].delete(path).status_code == 403
    assert clients["admin"].delete(path, headers={"X-CSRF-Token": "invalid"}).status_code == 403
    assert clients["admin"].delete(f"/api/v1/projects/{projects[1]['id']}/runs/{report[0]}").status_code == 404
    assert clients["admin"].get(f"/api/v1/runs/{report[0]}/artifacts/html").status_code == 200


@pytest.mark.parametrize("state", ["queued", "scanning", "exporting"])
def test_report_deletion_blocks_unfinished_jobs(workspace, state):
    factory, clients, projects, root = workspace
    report = add_report(factory, projects[0], root, state=state)
    response = clients["admin"].delete(f"/api/v1/projects/{projects[0]['id']}/runs/{report[0]}")
    assert response.status_code == 409
    with factory() as db:
        assert query(db, "SELECT state FROM cvex.report_job WHERE id=:j", j=report[0]).scalar() == state


def test_report_deletion_rolls_back_then_retries_failed_file_cleanup(workspace, monkeypatch):
    import cvex.projects as deletion
    import cvex.jobs as jobs
    factory, clients, projects, root = workspace
    report = add_report(factory, projects[0], root, state="failed", snapshot_only=True)
    path = f"/api/v1/projects/{projects[0]['id']}/runs/{report[0]}"
    directory = root / f"projects/{projects[0]['id']}/reports/{report[0]}"
    def fail(*args, **kwargs):
        raise OSError("simulated failure")
    with monkeypatch.context() as patch:
        patch.setattr(deletion, "audit", fail)
        assert clients["admin"].delete(path).status_code == 500
    with factory() as db:
        assert query(db, "SELECT 1 FROM cvex.report_snapshot WHERE job_id=:j", j=report[0]).scalar()
    assert directory.exists()
    with monkeypatch.context() as patch:
        patch.setattr(jobs.shutil, "rmtree", fail)
        response = clients["admin"].delete(path)
        assert response.status_code == 200 and response.json()["cleanup_pending"] is True
    with factory() as db:
        assert not query(db, "SELECT 1 FROM cvex.scan WHERE id=:s", s=report[1]).scalar()
    jobs.drain_artifact_cleanup(factory)
    assert not directory.exists()


def test_report_deletion_preserves_scan_referenced_by_another_snapshot(workspace):
    factory, clients, projects, root = workspace
    removed = add_report(factory, projects[0], root)
    kept = add_report(factory, projects[0], root)
    with factory() as db:
        query(db, "UPDATE cvex.report_snapshot SET scan_id=:s WHERE job_id=:j", s=removed[1], j=kept[0])
        db.commit()
    assert clients["admin"].delete(f"/api/v1/projects/{projects[0]['id']}/runs/{removed[0]}").status_code == 200
    with factory() as db:
        assert query(db, "SELECT 1 FROM cvex.scan WHERE id=:s", s=removed[1]).scalar()
        assert query(db, "SELECT 1 FROM cvex.finding_evidence WHERE finding_id=:f", f=removed[2]).scalar()
