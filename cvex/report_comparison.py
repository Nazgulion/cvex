"""Freeze finding-level additions into a report's existing immutable snapshot."""
import json
from collections import Counter

from cvex.workspace import query, safe_path


def annotate_new_findings(current, previous=None, *, baseline_id=None, baseline_created_at=None, partial=False):
    """Compare component/CVE identities, not severity totals or database finding IDs."""
    for row in current["findings"]:
        row.pop("new_finding", None)
        row.pop("new_finding_index", None)
    current["comparison"] = {"available": False, "new_count": 0, "baseline_report_id": baseline_id}
    if not isinstance(previous, dict) or not isinstance(previous.get("findings"), list):
        return
    previous_metadata = previous.get("metadata") or {}
    if not isinstance(previous_metadata, dict):
        return
    same_sbom = bool(current.get("metadata", {}).get("sbom_id")) and (
        current["metadata"]["sbom_id"] == previous_metadata.get("sbom_id"))

    def key(row):
        component = row["component"]
        identity = (str(component["id"]),) if same_sbom else (
            str(component.get("name") or "").strip().casefold(),
            str(component.get("normalized_version") or component.get("raw_version") or ""))
        return (*identity, row["vulnerability"]["id"])

    try:
        known = Counter(key(row) for row in previous["findings"])
    except (KeyError, TypeError, AttributeError):
        return  # An incomplete legacy payload cannot establish a trustworthy baseline.
    new_count = 0
    for row in current["findings"]:
        identity = key(row)
        if known[identity]:
            known[identity] -= 1
        else:
            new_count += 1
            row["new_finding"] = True
            row["new_finding_index"] = new_count
    current["comparison"] = {
        "available": True, "new_count": new_count, "baseline_report_id": baseline_id,
        "baseline_created_at": str(baseline_created_at or previous_metadata.get("generated_at") or ""),
        "baseline_release": previous_metadata.get("release"), "baseline_partial": partial,
        "identity_policy": "component_id_and_cve" if same_sbom else "component_name_version_and_cve",
    }


def compare_previous_report(db, job, findings):
    previous = query(db, """SELECT j.id,j.created_at,j.state,j.artifacts,s.payload
      FROM cvex.report_job j LEFT JOIN cvex.report_snapshot s ON s.job_id=j.id
      WHERE j.project_id=:p AND j.state IN ('succeeded','partial')
        AND (j.created_at,j.id)<(:created,:id)
      ORDER BY j.created_at DESC,j.id DESC LIMIT 1""",
      p=job["project_id"], created=job["created_at"], id=job["id"]).mappings().first()
    payload = None
    if previous:
        payload = (previous["payload"] or {}).get("findings")
        # Adopted pre-workspace reports have stored JSON, but no report_snapshot row.
        if payload is None and (previous["artifacts"] or {}).get("json"):
            try:
                payload = json.loads(safe_path(previous["artifacts"]["json"]).read_bytes())
            except (OSError, ValueError):
                pass  # No trustworthy baseline: do not label everything new.
    annotate_new_findings(findings, payload,
                          baseline_id=str(previous["id"]) if previous else None,
                          baseline_created_at=previous["created_at"] if previous else None,
                          partial=bool(previous and previous["state"] == "partial"))
