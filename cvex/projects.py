"""Transactional deletion of a workspace project, not shared intelligence."""
from cvex.workspace import audit, query, rows


class ProjectNotFound(ValueError):
    pass


class ProjectBusy(ValueError):
    pass


def delete_project(db, project_id, actor):
    # Coordinate retention, then use the scheduler's schedule -> project lock order.
    query(db, "SELECT pg_advisory_xact_lock(7401003)")
    target = f"project:{project_id}"
    query(db, "SELECT target FROM cvex.web_schedule WHERE target=:t FOR UPDATE", t=target)
    project = query(db, "SELECT * FROM cvex.project WHERE id=:p FOR UPDATE", p=project_id).mappings().first()
    if not project:
        raise ProjectNotFound("Project not found")
    # Claiming a queued job and deleting it cannot race past this row lock.
    jobs = rows(db, "SELECT id,state FROM cvex.report_job WHERE project_id=:p ORDER BY id FOR UPDATE", p=project_id)
    if any(job["state"] in {"scanning", "exporting"} for job in jobs):
        raise ProjectBusy("A report is running for this project. Wait for it to finish, then try again.")
    scans = rows(db, """SELECT scan_id FROM cvex.report_job WHERE project_id=:p AND scan_id IS NOT NULL
      UNION SELECT s.scan_id FROM cvex.report_snapshot s JOIN cvex.report_job j ON j.id=s.job_id
      WHERE j.project_id=:p AND s.scan_id IS NOT NULL""", p=project_id)
    path = f"projects/{project_id}"
    # Durable intent is committed with the database deletion. Files are never removed on rollback.
    query(db, "INSERT INTO cvex.artifact_cleanup(path) VALUES(:p) ON CONFLICT DO NOTHING", p=path)
    query(db, "DELETE FROM cvex.report_snapshot WHERE job_id IN (SELECT id FROM cvex.report_job WHERE project_id=:p)", p=project_id)
    query(db, "DELETE FROM cvex.report_job WHERE project_id=:p", p=project_id)
    for scan in scans:
        sid = scan["scan_id"]
        if query(db, """SELECT 1 FROM cvex.report_job WHERE scan_id=:s
          UNION ALL SELECT 1 FROM cvex.report_snapshot WHERE scan_id=:s""", s=sid).first():
            continue
        query(db, "DELETE FROM cvex.report_export WHERE scan_id=:s", s=sid)
        # Findings, evidence and component results cascade from their owned scan.
        query(db, "DELETE FROM cvex.scan WHERE id=:s", s=sid)
    query(db, "DELETE FROM cvex.web_schedule WHERE target=:t", t=target)
    query(db, "UPDATE cvex.project SET active_version_id=NULL WHERE id=:p", p=project_id)
    query(db, "DELETE FROM cvex.project_version WHERE project_id=:p", p=project_id)
    query(db, "DELETE FROM cvex.project WHERE id=:p", p=project_id)
    audit(db, actor, "project_deleted", project_id=project_id, company=project["company"],
          name=project["name"], reports_deleted=len(jobs))
    return path
