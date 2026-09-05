"""Explicit, idempotent adoption of regular v2 SBOMs and existing exported scans."""
import json
import shutil

from cvex.workspace import audit, query, rows, safe_path


def adopt_existing(db, config):
    from pathlib import Path
    documents = rows(db, """SELECT s.*,p.client_name,p.product_name,p.release_version FROM cvex.sbom_document s
      JOIN cvex.product p ON p.id=s.product_id WHERE s.format='spdx' ORDER BY s.imported_at""")
    count = 0
    for doc in documents:
        version = query(db, "SELECT id FROM cvex.project_version WHERE sbom_id=:s LIMIT 1", s=doc["id"]).scalar()
        if version:
            continue
        pid = query(db, "SELECT id FROM cvex.project WHERE company=:c AND name=:n ORDER BY created_at LIMIT 1", c=doc["client_name"], n=doc["product_name"]).scalar()
        if not pid:
            pid = query(db, "INSERT INTO cvex.project(company,name) VALUES(:c,:n) RETURNING id", c=doc["client_name"], n=doc["product_name"]).scalar()
            query(db, "INSERT INTO cvex.web_schedule(target) VALUES(:t)", t=f"project:{pid}")
        version = query(db, """INSERT INTO cvex.project_version(project_id,sbom_id,label,filename,created_at)
          VALUES(:p,:s,:l,:f,:d) RETURNING id""", p=pid, s=doc["id"], l=doc["release_version"], f=(doc["name"] or "sbom")[:200]+".json", d=doc["imported_at"]).scalar()
        relative = f"projects/{pid}/uploads/{version}.json"
        path = safe_path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc["raw_payload"],indent=2),encoding="utf-8")
        query(db,"UPDATE cvex.project_version SET upload_path=:r WHERE id=:v",r=relative,v=version)
        query(db,"UPDATE cvex.project SET active_version_id=:v WHERE id=:p",v=version,p=pid)
        for scan in rows(db,"SELECT * FROM cvex.scan WHERE sbom_document_id=:s AND status='succeeded' ORDER BY created_at",s=doc["id"]):
            exports=rows(db,"SELECT DISTINCT ON(export_type) * FROM cvex.report_export WHERE scan_id=:s ORDER BY export_type,generated_at DESC",s=scan["id"])
            names={"scan_summary":"summary","findings_json":"json","findings_csv":"csv","findings_html":"html"}
            selected={names[e["export_type"]]:e for e in exports if e["export_type"] in names}
            if set(selected)!={"summary","json","csv","html"}:
                continue
            report_root=Path(config.paths.report_root).resolve()
            paths={kind:(report_root/e["path"]).resolve() for kind,e in selected.items()}
            if any(not p.is_relative_to(report_root) or not p.is_file() for p in paths.values()):
                continue
            jid=query(db,"""INSERT INTO cvex.report_job(project_id,version_id,trigger,state,created_at,started_at,finished_at,scan_id)
              VALUES(:p,:v,'adopted','succeeded',:c,:s,:f,:sid) RETURNING id""",p=pid,v=version,c=scan["created_at"],s=scan["started_at"],f=scan["finished_at"],sid=scan["id"]).scalar()
            folder=f"projects/{pid}/reports/{jid}"
            safe_path(folder).mkdir(parents=True,exist_ok=True)
            artifacts={}
            for kind,path in paths.items():
                relative=folder+"/"+path.name
                shutil.copyfile(path,safe_path(relative))
                artifacts[kind]=relative
            summary=json.loads(paths["summary"].read_text())
            brief={"counts":summary.get("counts",{}),"source_freshness":summary.get("source_freshness",{})}
            query(db,"UPDATE cvex.report_job SET artifacts=CAST(:a AS jsonb),summary=CAST(:s AS jsonb) WHERE id=:id",a=json.dumps(artifacts),s=json.dumps(brief),id=jid)
        count+=1
        audit(db,"adoption","sbom_adopted",project_id=pid,sbom_id=doc["id"])
    db.commit()
    return count
