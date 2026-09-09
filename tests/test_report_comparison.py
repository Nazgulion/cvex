from collections import Counter
from copy import deepcopy
import json
import os

import pytest

from cvex.exporter import _render_findings_html
from cvex.report_comparison import annotate_new_findings, compare_previous_report
from cvex.workspace import query
from test_project_deletion import workspace, add_report


def finding(cve, component_id="component-1", version="1.0", severity="high"):
    return {
        "component": {"id": component_id, "name": "curl", "raw_version": version, "normalized_version": version},
        "vulnerability": {"id": cve, "severity": severity, "score": 8.0, "status": "active", "description": "Example",
                          "sources": ["nvd"], "source_advisory_ids": [cve]},
        "matched": {"versions": [version], "identities": [], "match_types": [], "confidence": "high", "warnings": [], "reasons": []},
        "decision": {"status": "matched_strong_evidence", "evidence_strength": "strong", "reason": "Matched", "factors": []},
    }


def payload(findings, sbom="sbom-1"):
    return {"metadata": {"sbom_id": sbom, "generated_at": "2026-09-09T10:00:00Z", "release": "1.0",
                         "client": "Orion", "product": "Gateway", "scan_id": "test-scan"},
            "findings": findings,
            "counts": {"findings_total": len(findings), "affected_components": len({r['component']['id'] for r in findings}),
                       "severity": dict(Counter(r['vulnerability']['severity'] for r in findings))}}


def test_exact_additions_not_changed_severity_or_description():
    previous = payload([finding("CVE-2026-0001")])
    unchanged = deepcopy(previous)
    current = payload([finding("CVE-2026-0001", severity="critical"), finding("CVE-2026-0002")])
    annotate_new_findings(current, previous, baseline_id="old-report")
    assert previous == unchanged
    assert not current["findings"][0].get("new_finding")
    assert current["findings"][1]["new_finding"] is True
    assert current["comparison"]["new_count"] == 1
    assert current["comparison"]["baseline_report_id"] == "old-report"


def test_new_and_removed_findings_with_unchanged_totals():
    current = payload([finding("CVE-2026-0002")])
    annotate_new_findings(current, payload([finding("CVE-2026-0001")]))
    assert current["findings"][0]["new_finding"] is True


def test_first_missing_and_empty_baselines_are_distinct():
    current = payload([finding("CVE-2026-0001")])
    for baseline in (None, {}, {"findings": [{}]}):
        annotate_new_findings(current, baseline)
        assert current["comparison"]["available"] is False
        assert not current["findings"][0].get("new_finding")
    annotate_new_findings(current, payload([]))
    assert current["comparison"]["available"] is True
    assert current["comparison"]["new_count"] == 1


def test_cross_sbom_keys_ignore_regenerated_uuids_but_preserve_version_and_multiplicity():
    previous = payload([finding("CVE-2026-0001")])
    current = payload([finding("CVE-2026-0001", "new-id"), finding("CVE-2026-0001", "second-instance"),
                       finding("CVE-2026-0001", "new-version", "2.0")], "sbom-2")
    annotate_new_findings(current, previous)
    assert not current["findings"][0].get("new_finding")
    assert current["comparison"]["new_count"] == 2
    assert current["comparison"]["identity_policy"] == "component_name_version_and_cve"


def test_same_cve_on_different_component_is_a_new_finding():
    current = payload([finding("CVE-2026-0001", "component-2")])
    annotate_new_findings(current, payload([finding("CVE-2026-0001")]))
    assert current["comparison"]["new_count"] == 1


def test_html_highlights_exact_finding_and_opens_component_without_losing_max_severity():
    current = payload([finding("CVE-2026-0001", severity="critical"), finding("CVE-2026-0002", severity="low")])
    annotate_new_findings(current, payload([finding("CVE-2026-0001", severity="critical")]),
                          baseline_id="baseline", baseline_created_at='<script>alert(1)</script>', partial=True)
    output = _render_findings_html(current)
    assert output.count('class="finding-card new-finding"') == 1
    assert 'id="new-finding-1"' in output and 'href="#new-finding-1"' in output
    assert '<details class="component-summary" open>' in output
    assert 'NEW FINDING</div>' in output
    assert '1 new finding since the previous report' in output
    assert 'partial baseline' in output
    assert '<script>alert(1)</script>' not in output
    assert '&lt;script&gt;' in output
    # Component summary still reports its critical finding, although a low new finding is listed first.
    summary = output.split('<details class="component-summary" open>')[1].split('</summary>')[0]
    assert 'sev-critical' in summary


def test_no_additions_and_unavailable_baseline_have_no_highlighted_cards():
    current = payload([finding("CVE-2026-0001")])
    annotate_new_findings(current, deepcopy(current))
    output = _render_findings_html(current)
    assert '0 new findings since the previous report' in output
    assert 'class="finding-card new-finding"' not in output
    annotate_new_findings(current)
    assert 'establishes a baseline' in _render_findings_html(current)


@pytest.mark.skipif(not os.getenv("CVEX_TEST_DATABASE_URL"), reason="requires disposable PostgreSQL")
def test_project_baseline_selection_and_frozen_metadata(workspace):
    factory, clients, projects, root = workspace
    old = add_report(factory, projects[0], root)
    add_report(factory, projects[0], root, state="failed")
    add_report(factory, projects[1], root)  # A newer report in another project is not a baseline.
    previous = payload([finding("CVE-2026-0001")])
    with factory() as db:
        query(db, "UPDATE cvex.report_snapshot SET payload=CAST(:p AS jsonb) WHERE job_id=:j", j=old[0], p=json.dumps({"findings": previous}))
        db.commit()
    jid = clients["admin"].post(f"/api/v1/projects/{projects[0]['id']}/runs").json()["id"]
    current = payload([finding("CVE-2026-0001"), finding("CVE-2026-0002")])
    with factory() as db:
        job = query(db, "SELECT * FROM cvex.report_job WHERE id=CAST(:j AS uuid)", j=jid).mappings().one()
        compare_previous_report(db, job, current)
        assert current["comparison"]["baseline_report_id"] == str(old[0])
        assert current["comparison"]["new_count"] == 1
        query(db, "INSERT INTO cvex.report_snapshot(job_id,payload) VALUES(CAST(:j AS uuid),CAST(:p AS jsonb))", j=jid, p=json.dumps({"findings": current}))
        db.commit()
    assert clients["admin"].delete(f"/api/v1/projects/{projects[0]['id']}/runs/{old[0]}").status_code == 200
    with factory() as db:
        frozen = query(db, "SELECT payload FROM cvex.report_snapshot WHERE job_id=CAST(:j AS uuid)", j=jid).scalar()
        assert frozen["findings"]["comparison"] == current["comparison"]
        assert frozen["findings"]["findings"][1]["new_finding"] is True
