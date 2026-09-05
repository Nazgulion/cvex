from __future__ import annotations

import json
import csv
import html
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cvex.config import CvexConfig
from cvex.db.models import (
    ComponentIdentity,
    FindingEvidence,
    Product,
    ReportExport,
    SbomComponent,
    SbomDocument,
    Scan,
    ScanComponentResult,
    SourceRun,
    SourcePayload,
    SourceVulnerability,
    Vulnerability,
    VulnerabilityFinding,
)
from cvex.time import isoformat_z, utcnow
from cvex.util import sha256_bytes


def export_summary(session: Session, config: CvexConfig, scan_id: str, out_dir: str | None = None) -> str:
    scan = session.execute(select(Scan).where(Scan.id == scan_id)).scalar_one()
    sbom = session.execute(select(SbomDocument).where(SbomDocument.id == scan.sbom_document_id)).scalar_one()
    product = session.execute(select(Product).where(Product.id == sbom.product_id)).scalar_one()
    run = SourceRun(source="reporter", run_type="export", status="running", details={"scan_id": scan_id, "type": "summary"})
    session.add(run)
    session.flush()

    export_date = utcnow().date().isoformat()
    relative_dir = Path(export_date) / str(scan.id) / str(run.id)
    root = Path(out_dir or config.paths.report_root)
    full_dir = root / relative_dir
    full_dir.mkdir(parents=True, exist_ok=True)
    output_path = full_dir / "scan-summary.json"

    payload = build_summary_payload(session, config, scan, sbom, product, str(run.id))
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    digest = sha256_bytes(output_path.read_bytes())
    relative_path = relative_dir / "scan-summary.json"
    session.add(
        ReportExport(
            scan_id=scan.id,
            run_id=run.id,
            export_type="scan_summary",
            path=str(relative_path),
            sha256=digest,
        )
    )
    run.status = "succeeded"
    run.finished_at = utcnow()
    session.commit()
    return str(output_path)


def export_findings(session: Session, config: CvexConfig, scan_id: str, out_dir: str | None = None) -> dict[str, str]:
    scan = session.execute(select(Scan).where(Scan.id == scan_id)).scalar_one()
    sbom = session.execute(select(SbomDocument).where(SbomDocument.id == scan.sbom_document_id)).scalar_one()
    product = session.execute(select(Product).where(Product.id == sbom.product_id)).scalar_one()
    run = SourceRun(source="reporter", run_type="export", status="running", details={"scan_id": scan_id, "type": "findings"})
    session.add(run)
    session.flush()

    export_date = utcnow().date().isoformat()
    relative_dir = Path(export_date) / str(scan.id) / str(run.id)
    root = Path(out_dir or config.paths.report_root)
    full_dir = root / relative_dir
    full_dir.mkdir(parents=True, exist_ok=True)

    payload = build_findings_payload(session, config, scan, sbom, product, str(run.id))
    paths = {
        "json": full_dir / "findings.json",
        "csv": full_dir / "findings.csv",
        "html": full_dir / "findings.html",
    }
    paths["json"].write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    _write_findings_csv(paths["csv"], payload["findings"])
    paths["html"].write_text(_render_findings_html(payload), encoding="utf-8")

    for key, path in paths.items():
        session.add(
            ReportExport(
                scan_id=scan.id,
                run_id=run.id,
                export_type=f"findings_{key}",
                path=str(relative_dir / path.name),
                sha256=sha256_bytes(path.read_bytes()),
            )
        )
    run.status = "succeeded"
    run.finished_at = utcnow()
    session.commit()
    return {key: str(path) for key, path in paths.items()}


def export_onfly(session: Session, config: CvexConfig, scan_id: str, out_dir: str | None = None) -> dict[str, str]:
    scan = session.execute(select(Scan).where(Scan.id == scan_id)).scalar_one()
    sbom = session.execute(select(SbomDocument).where(SbomDocument.id == scan.sbom_document_id)).scalar_one()
    product = session.execute(select(Product).where(Product.id == sbom.product_id)).scalar_one()
    if (scan.source_snapshot or {}).get("scan_type") != "onfly":
        raise ValueError("scan is not an on-fly scan")
    run = SourceRun(source="reporter", run_type="export", status="running", details={"scan_id": scan_id, "type": "onfly"})
    session.add(run)
    session.flush()

    export_date = utcnow().date().isoformat()
    relative_dir = Path(export_date) / str(scan.id) / str(run.id)
    root = Path(out_dir or config.paths.report_root)
    full_dir = root / relative_dir
    full_dir.mkdir(parents=True, exist_ok=True)

    payload = build_onfly_payload(session, config, scan, sbom, product, str(run.id))
    paths = {
        "json": full_dir / "onfly.json",
        "csv": full_dir / "onfly.csv",
        "html": full_dir / "onfly.html",
    }
    paths["json"].write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    _write_onfly_csv(paths["csv"], payload["results"])
    paths["html"].write_text(_render_onfly_html(payload), encoding="utf-8")

    for key, path in paths.items():
        session.add(
            ReportExport(
                scan_id=scan.id,
                run_id=run.id,
                export_type=f"onfly_{key}",
                path=str(relative_dir / path.name),
                sha256=sha256_bytes(path.read_bytes()),
            )
        )
    run.status = "succeeded"
    run.finished_at = utcnow()
    session.commit()
    return {key: str(path) for key, path in paths.items()}


def build_onfly_payload(
    session: Session,
    config: CvexConfig,
    scan: Scan,
    sbom: SbomDocument,
    product: Product,
    export_run_id: str,
) -> dict[str, Any]:
    rows = session.execute(
        select(VulnerabilityFinding, Vulnerability, SbomComponent, FindingEvidence)
        .join(Vulnerability, VulnerabilityFinding.vulnerability_id == Vulnerability.id)
        .join(SbomComponent, VulnerabilityFinding.component_id == SbomComponent.id)
        .join(FindingEvidence, FindingEvidence.finding_id == VulnerabilityFinding.id, isouter=True)
        .where(VulnerabilityFinding.scan_id == scan.id)
        .order_by(SbomComponent.name, Vulnerability.cve_id)
    ).all()
    results = []
    status_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    delta_counts: Counter[str] = Counter()
    for finding, vuln, component, evidence in rows:
        matched_range = evidence.matched_range if evidence else {}
        status = finding.status
        delta_label = matched_range.get("delta_label") or "new_hit"
        status_counts[status] += 1
        severity_counts[finding.display_severity or "unknown"] += 1
        delta_counts[delta_label] += 1
        results.append(
            {
                "component": {
                    "id": str(component.id),
                    "component_id": component.source_component_id,
                    "name": component.name,
                    "raw_version": component.raw_version,
                    "normalized_version": component.normalized_version,
                    "identities": _component_identities(session, component.id),
                },
                "cve": {
                    "id": vuln.cve_id,
                    "status": vuln.status,
                    "description": vuln.description,
                    "sources": matched_range.get("sources") or [],
                    "source_modified": matched_range.get("source_modified") or {},
                },
                "result": {
                    "status": status,
                    "confidence": finding.confidence,
                    "severity": finding.display_severity or "unknown",
                    "score": finding.display_score,
                    "severity_source": matched_range.get("severity_source") or "unknown",
                    "delta_label": delta_label,
                    "reason": evidence.reason if evidence else None,
                    "source": evidence.source if evidence else None,
                    "match_type": evidence.match_type if evidence else None,
                    "matched_identity_type": evidence.matched_identity_type if evidence else None,
                    "matched_identity_value": evidence.matched_identity_value if evidence else None,
                    "matched_version": evidence.matched_version if evidence else None,
                    "matched_range": matched_range,
                    "warnings": evidence.warnings if evidence else [],
                },
            }
        )
    results.sort(key=_onfly_sort_key)
    return {
        "metadata": {
            "scan_id": str(scan.id),
            "export_run_id": export_run_id,
            "watchlist_path": (scan.source_snapshot or {}).get("watchlist_path"),
            "watchlist_sha256": (scan.source_snapshot or {}).get("watchlist_sha256"),
            "client": product.client_name,
            "product": product.product_name,
            "release": product.release_version,
            "generated_at": isoformat_z(utcnow()),
        },
        "source_freshness": scan.source_snapshot,
        "attribution": config.attribution,
        "counts": {
            "results_total": len(results),
            "status": dict(status_counts),
            "severity": dict(severity_counts),
            "delta": dict(delta_counts),
        },
        "warnings": (scan.source_snapshot or {}).get("warnings") or [],
        "results": results,
    }


def build_summary_payload(
    session: Session,
    config: CvexConfig,
    scan: Scan,
    sbom: SbomDocument,
    product: Product,
    export_run_id: str,
) -> dict[str, Any]:
    results = session.execute(
        select(ScanComponentResult, SbomComponent)
        .join(SbomComponent, ScanComponentResult.component_id == SbomComponent.id)
        .where(ScanComponentResult.scan_id == scan.id)
        .order_by(SbomComponent.name)
    ).all()
    findings_by_component = _findings_by_component(session, scan.id)
    components = []
    status_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()
    active_risk = 0
    inactive_warnings = 0

    for result, component in results:
        status_counts[result.status] += 1
        findings = findings_by_component.get(str(component.id), [])
        finding_rows = []
        for finding, vuln, evidence in findings:
            if finding.inactive:
                inactive_warnings += 1
            else:
                active_risk += 1
            if finding.display_severity:
                severity_counts[finding.display_severity] += 1
            confidence_counts[finding.confidence] += 1
            finding_rows.append(
                {
                    "cve_id": vuln.cve_id,
                    "severity": finding.display_severity,
                    "score": finding.display_score,
                    "confidence": finding.confidence,
                    "inactive": finding.inactive,
                    "analysis_state": "in_triage",
                    "match_reason": evidence.reason if evidence else None,
                    "decision": _build_match_decision(
                        {
                            "matched": _matched_from_summary_evidence(finding, evidence),
                            "vulnerability": {
                                "id": vuln.cve_id,
                                "status": vuln.status,
                                "inactive": finding.inactive,
                            },
                        }
                    ),
                    "sources": sorted({ev.source for _, _, ev in findings if ev and str(finding.id) == str(ev.finding_id)}),
                    "warnings": evidence.warnings if evidence else [],
                }
            )
        components.append(
            {
                "component_id": str(component.id),
                "name": component.name,
                "raw_version": component.raw_version,
                "normalized_version": component.normalized_version,
                "identities": _component_identities(session, component.id),
                "status": result.status,
                "findings_count": len(findings),
                "reason_code": result.reason_code,
                "reason_message": result.reason_message,
                "warnings": result.warnings,
                "findings": finding_rows,
            }
        )

    return {
        "metadata": {
            "scan_id": str(scan.id),
            "export_run_id": export_run_id,
            "sbom_id": str(sbom.id),
            "sbom_sha256": sbom.content_sha256,
            "client": product.client_name,
            "product": product.product_name,
            "release": product.release_version,
            "generated_at": isoformat_z(utcnow()),
        },
        "source_freshness": scan.source_snapshot,
        "attribution": config.attribution,
        "counts": {
            "components_total": len(results),
            "matched": status_counts["matched"],
            "unmatched": status_counts["unmatched"],
            "not_assessed": status_counts["not_assessed"],
            "error": status_counts["error"],
            "findings_total": sum(len(v) for v in findings_by_component.values()),
            "active_risk_findings": active_risk,
            "inactive_warnings": inactive_warnings,
            "severity": dict(severity_counts),
            "confidence": dict(confidence_counts),
        },
        "warnings": _top_level_warnings(scan.source_snapshot),
        "components": components,
    }


def build_findings_payload(
    session: Session,
    config: CvexConfig,
    scan: Scan,
    sbom: SbomDocument,
    product: Product,
    export_run_id: str,
) -> dict[str, Any]:
    rows = session.execute(
        select(VulnerabilityFinding, Vulnerability, SbomComponent, FindingEvidence)
        .join(Vulnerability, VulnerabilityFinding.vulnerability_id == Vulnerability.id)
        .join(SbomComponent, VulnerabilityFinding.component_id == SbomComponent.id)
        .join(FindingEvidence, FindingEvidence.finding_id == VulnerabilityFinding.id, isouter=True)
        .where(VulnerabilityFinding.scan_id == scan.id)
        .order_by(SbomComponent.name, Vulnerability.cve_id)
    ).all()
    cve_ids = [vuln.cve_id for _, vuln, _, _ in rows]
    source_vulns = _source_vulnerabilities_by_cve(session, cve_ids)
    source_advisory_ids = _source_advisory_ids_by_cve(session, cve_ids)
    grouped: dict[str, dict[str, Any]] = {}
    severity_counts: Counter[str] = Counter()
    affected_components = set()

    for finding, vuln, component, evidence in rows:
        key = str(finding.id)
        if key not in grouped:
            description = vuln.description
            sources = sorted({sv.source for sv in source_vulns.get(vuln.cve_id, [])})
            if evidence and evidence.source not in sources:
                sources.append(evidence.source)
                sources.sort()
            grouped[key] = {
                "component": {
                    "id": str(component.id),
                    "name": component.name,
                    "raw_version": component.raw_version,
                    "normalized_version": component.normalized_version,
                    "identities": _component_identities(session, component.id),
                },
                "matched": {
                    "versions": [],
                    "identities": [],
                    "match_types": [],
                    "confidence": finding.confidence,
                    "reasons": [],
                    "warnings": [],
                    "version_conflict": False,
                    "cpe_version": None,
                    "package_version": None,
                    "cpe_version_matched": False,
                    "package_version_matched": False,
                    "identity_inferred": False,
                    "inferred_from_repo": None,
                    "distro_candidate": False,
                    "ecosystem": None,
                    "package_name": None,
                },
                "vulnerability": {
                    "id": vuln.cve_id,
                    "severity": finding.display_severity,
                    "score": finding.display_score,
                    "status": vuln.status,
                    "inactive": finding.inactive,
                    "description": description,
                    "sources": sources,
                    "source_advisory_ids": source_advisory_ids.get(vuln.cve_id, []),
                },
            }
            affected_components.add(str(component.id))
            if finding.display_severity:
                severity_counts[finding.display_severity] += 1
        if evidence:
            _append_unique(grouped[key]["matched"]["versions"], evidence.matched_version)
            _append_unique(grouped[key]["matched"]["identities"], evidence.matched_identity_value)
            _append_unique(grouped[key]["matched"]["match_types"], evidence.match_type)
            _append_unique(grouped[key]["matched"]["reasons"], evidence.reason)
            _merge_version_match_details(grouped[key]["matched"], evidence.matched_range or {})
            for warning in evidence.warnings or []:
                if warning not in grouped[key]["matched"]["warnings"]:
                    grouped[key]["matched"]["warnings"].append(warning)

    findings = list(grouped.values())
    for finding in findings:
        finding["decision"] = _build_match_decision(finding)
        finding["matched"]["warnings"] = _compact_warnings(finding["matched"]["warnings"])
    return {
        "metadata": {
            "scan_id": str(scan.id),
            "export_run_id": export_run_id,
            "sbom_id": str(sbom.id),
            "sbom_sha256": sbom.content_sha256,
            "client": product.client_name,
            "product": product.product_name,
            "release": product.release_version,
            "generated_at": isoformat_z(utcnow()),
        },
        "source_freshness": scan.source_snapshot,
        "attribution": config.attribution,
        "counts": {
            "findings_total": len(findings),
            "affected_components": len(affected_components),
            "severity": dict(severity_counts),
        },
        "warnings": _top_level_warnings(scan.source_snapshot),
        "findings": findings,
    }


def _findings_by_component(session: Session, scan_id: str):
    rows = session.execute(
        select(VulnerabilityFinding, Vulnerability, FindingEvidence)
        .join(Vulnerability, VulnerabilityFinding.vulnerability_id == Vulnerability.id)
        .join(FindingEvidence, FindingEvidence.finding_id == VulnerabilityFinding.id, isouter=True)
        .where(VulnerabilityFinding.scan_id == scan_id)
    ).all()
    grouped = defaultdict(list)
    seen = set()
    for finding, vuln, evidence in rows:
        key = (str(finding.id), str(evidence.id) if evidence else "")
        if key in seen:
            continue
        seen.add(key)
        grouped[str(finding.component_id)].append((finding, vuln, evidence))
    return grouped


def _component_identities(session: Session, component_id: str) -> list[dict[str, str]]:
    identities = session.execute(
        select(ComponentIdentity).where(ComponentIdentity.component_id == component_id).order_by(ComponentIdentity.identity_type)
    ).scalars().all()
    return [{"type": identity.identity_type, "value": identity.identity_value} for identity in identities]


def _source_vulnerabilities_by_cve(session: Session, cve_ids: list[str]) -> dict[str, list[SourceVulnerability]]:
    if not cve_ids:
        return {}
    rows = session.execute(
        select(SourcePayload).where(SourcePayload.cve_id.in_(sorted(set(cve_ids)))).order_by(SourcePayload.source)
    ).scalars().all()
    grouped: dict[str, list[SourceVulnerability]] = defaultdict(list)
    descriptions = dict(session.execute(select(Vulnerability.cve_id, Vulnerability.description).where(Vulnerability.cve_id.in_(sorted(set(cve_ids))))).all())
    for row in rows:
        grouped[row.cve_id].append(SourceVulnerability(source=row.source, primary_id=row.cve_id, description=descriptions.get(row.cve_id), source_record_id=row.id))
    return grouped


def _source_advisory_ids_by_cve(session: Session, cve_ids: list[str]) -> dict[str, list[str]]:
    return {}


def _preferred_description(source_vulns: list[SourceVulnerability]) -> str | None:
    by_source = {source_vuln.source: source_vuln.description for source_vuln in source_vulns if source_vuln.description}
    return by_source.get("cve") or by_source.get("nvd") or next(iter(by_source.values()), None)


def _append_unique(values: list[str], value: str | None) -> None:
    if value and value not in values:
        values.append(value)


def _write_findings_csv(path: Path, findings: list[dict[str, Any]]) -> None:
    columns = [
        "component_name",
        "raw_version",
        "normalized_version",
        "matched_version",
        "matched_identity",
        "version_conflict",
        "cpe_version",
        "package_version",
        "cpe_version_matched",
        "package_version_matched",
        "identity_inferred",
        "inferred_from_repo",
        "distro_candidate",
        "ecosystem",
        "package_name",
        "cve",
        "source_advisory_ids",
        "severity",
        "score",
        "status",
        "confidence",
        "decision",
        "evidence_strength",
        "decision_reason",
        "decision_factors",
        "description",
        "match_reason",
        "warnings",
        "sources",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for row in findings:
            component = row["component"]
            matched = row["matched"]
            vulnerability = row["vulnerability"]
            writer.writerow(
                {
                    "component_name": component["name"],
                    "raw_version": component["raw_version"] or "",
                    "normalized_version": component["normalized_version"] or "",
                    "matched_version": "; ".join(matched["versions"]),
                    "matched_identity": "; ".join(matched["identities"]),
                    "version_conflict": matched["version_conflict"],
                    "cpe_version": matched["cpe_version"] or "",
                    "package_version": matched["package_version"] or "",
                    "cpe_version_matched": matched["cpe_version_matched"],
                    "package_version_matched": matched["package_version_matched"],
                    "identity_inferred": matched["identity_inferred"],
                    "inferred_from_repo": matched["inferred_from_repo"] or "",
                    "distro_candidate": matched["distro_candidate"],
                    "ecosystem": matched["ecosystem"] or "",
                    "package_name": matched["package_name"] or "",
                    "cve": vulnerability["id"],
                    "source_advisory_ids": "; ".join(vulnerability["source_advisory_ids"]),
                    "severity": vulnerability["severity"] or "",
                    "score": vulnerability["score"] if vulnerability["score"] is not None else "",
                    "status": vulnerability["status"],
                    "confidence": matched["confidence"],
                    "decision": row["decision"]["status"],
                    "evidence_strength": row["decision"]["evidence_strength"],
                    "decision_reason": row["decision"]["reason"],
                    "decision_factors": "; ".join(row["decision"]["factors"]),
                    "description": vulnerability["description"] or "",
                    "match_reason": "; ".join(matched["reasons"]),
                    "warnings": _format_warnings(matched["warnings"]),
                    "sources": ",".join(vulnerability["sources"]),
                }
            )


def _write_onfly_csv(path: Path, results: list[dict[str, Any]]) -> None:
    columns = [
        "status",
        "delta_label",
        "component_id",
        "component_name",
        "raw_version",
        "normalized_version",
        "cve",
        "severity",
        "severity_source",
        "score",
        "confidence",
        "source",
        "match_type",
        "matched_identity_type",
        "matched_identity_value",
        "matched_version",
        "reason",
        "sources",
        "source_modified",
        "warnings",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for row in results:
            component = row["component"]
            cve = row["cve"]
            result = row["result"]
            writer.writerow(
                {
                    "status": result["status"],
                    "delta_label": result["delta_label"],
                    "component_id": component["component_id"],
                    "component_name": component["name"],
                    "raw_version": component["raw_version"] or "",
                    "normalized_version": component["normalized_version"] or "",
                    "cve": cve["id"],
                    "severity": result["severity"],
                    "severity_source": result["severity_source"],
                    "score": result["score"] if result["score"] is not None else "",
                    "confidence": result["confidence"],
                    "source": result["source"] or "",
                    "match_type": result["match_type"] or "",
                    "matched_identity_type": result["matched_identity_type"] or "",
                    "matched_identity_value": result["matched_identity_value"] or "",
                    "matched_version": result["matched_version"] or "",
                    "reason": result["reason"] or "",
                    "sources": ",".join(cve["sources"]),
                    "source_modified": json.dumps(cve["source_modified"], sort_keys=True),
                    "warnings": _format_warnings(result["warnings"]),
                }
            )


def _render_onfly_html(payload: dict[str, Any]) -> str:
    metadata = payload["metadata"]
    counts = payload["counts"]
    hits = [row for row in payload["results"] if row["result"]["status"] != "ignored"]
    ignored = [row for row in payload["results"] if row["result"]["status"] == "ignored"]
    hit_rows = "\n".join(_render_onfly_row(row) for row in hits)
    if not hit_rows:
        hit_rows = '<tr><td colspan="7" class="empty">No on-fly hits.</td></tr>'
    ignored_groups = _group_onfly_ignored(ignored)
    ignored_html = "\n".join(_render_ignored_group(label, rows) for label, rows in ignored_groups)
    if not ignored_html:
        ignored_html = '<div class="muted">No ignored comparisons.</div>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CVEX On-Fly Report</title>
  <style>
    :root {{
      --bg: #101214;
      --panel: #181c20;
      --panel-2: #20262c;
      --ink: #edf2f7;
      --muted: #9aa7b4;
      --line: #303840;
      --accent: #3cc6a8;
      --critical: #ff5c7a;
      --high: #ff8659;
      --medium: #f4bf50;
      --low: #65d887;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--ink); font: 12px/1.45 Arial, Helvetica, sans-serif; }}
    .shell {{ padding: 18px 20px 30px; }}
    h1 {{ margin: 0; font-size: 22px; letter-spacing: 0; }}
    .subtitle {{ color: var(--muted); margin-top: 4px; }}
    .meta, .metrics {{ display: grid; grid-template-columns: repeat(4, minmax(140px, 1fr)); gap: 8px; margin: 12px 0; }}
    .box {{ background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 9px 10px; min-width: 0; overflow-wrap: anywhere; }}
    .label {{ color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .04em; }}
    .value {{ margin-top: 2px; font-weight: 700; }}
    .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; margin-top: 12px; }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
    th {{ background: #12161a; color: var(--ink); text-align: left; padding: 8px; border-bottom: 1px solid var(--line); font-size: 10px; text-transform: uppercase; }}
    td {{ padding: 9px 8px; border-bottom: 1px solid #252c33; vertical-align: top; overflow-wrap: anywhere; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; }}
    .muted {{ color: var(--muted); }}
    .pill {{ display: inline-flex; border: 1px solid var(--line); border-radius: 999px; padding: 2px 7px; margin: 0 4px 4px 0; font-weight: 700; font-size: 10px; background: #222932; }}
    .confirmed {{ color: var(--low); background: #14291d; border-color: #2d6844; }}
    .probable {{ color: var(--medium); background: #302511; border-color: #6f5520; }}
    .possible {{ color: var(--high); background: #351d17; border-color: #794231; }}
    .ignored {{ color: var(--muted); background: #20252d; }}
    .sev-critical {{ color: var(--critical); }}
    .sev-high {{ color: var(--high); }}
    .sev-medium {{ color: var(--medium); }}
    .sev-low {{ color: var(--low); }}
    details {{ margin: 8px 0; }}
    summary {{ cursor: pointer; color: var(--accent); font-weight: 700; }}
    .ignored-group {{ background: var(--panel-2); border: 1px solid var(--line); border-radius: 6px; padding: 8px; margin-top: 8px; }}
    .empty {{ text-align: center; color: var(--muted); padding: 22px; }}
    @media (max-width: 900px) {{ .meta, .metrics {{ grid-template-columns: 1fr 1fr; }} .panel {{ overflow-x: auto; }} table {{ min-width: 900px; }} }}
  </style>
</head>
<body>
  <div class="shell">
    <h1>CVEX On-Fly</h1>
    <div class="subtitle">Delta scan of modified local CVE/NVD records against the watchlist</div>
    <div class="meta">
      {_box("Client", metadata["client"])}
      {_box("Product", metadata["product"])}
      {_box("Release", metadata["release"])}
      {_box("Scan ID", metadata["scan_id"])}
    </div>
    <div class="metrics">
      {_box("Results", counts["results_total"])}
      {_box("Status", _render_count_pills(counts["status"], "onfly"))}
      {_box("Delta", _render_count_pills(counts["delta"], "onfly"))}
      {_box("Severity", _render_count_pills(counts["severity"], "sev"))}
    </div>
    <div class="panel">
      <table>
        <thead><tr><th>Status</th><th>Component</th><th>CVE</th><th>Severity</th><th>Evidence</th><th>Delta</th><th>Reason</th></tr></thead>
        <tbody>{hit_rows}</tbody>
      </table>
    </div>
    <details>
      <summary>Ignored comparisons ({len(ignored)})</summary>
      {ignored_html}
    </details>
  </div>
</body>
</html>
"""


def _render_onfly_row(row: dict[str, Any]) -> str:
    component = row["component"]
    cve = row["cve"]
    result = row["result"]
    status = result["status"]
    severity = result["severity"] or "unknown"
    return f"""<tr>
  <td>{_pill(status, status)}</td>
  <td><div class="value">{_e(component["name"])}</div><div class="muted mono">{_e(component["normalized_version"])}</div></td>
  <td><div class="mono">{_e(cve["id"])}</div><div class="muted">{_e(', '.join(cve["sources"]))}</div></td>
  <td><span class="sev-{_class_token(severity)}">{_e(severity)}</span><div class="muted">{_e(result["severity_source"])}</div></td>
  <td><div>{_e(result["match_type"])}</div><div class="muted mono">{_e(result["matched_identity_value"])}</div></td>
  <td>{_pill(result["delta_label"], "ignored" if result["delta_label"] == "known_cve_update" else "possible")}</td>
  <td>{_e(result["reason"])}</td>
</tr>"""


def _group_onfly_ignored(rows: list[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = row["result"].get("reason") or "Ignored"
        groups[key].append(row)
    return sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))


def _render_ignored_group(label: str, rows: list[dict[str, Any]]) -> str:
    items = "".join(
        f'<li><span class="mono">{_e(row["cve"]["id"])}</span> / {_e(row["component"]["name"])} / {_e(row["result"]["match_type"])}</li>'
        for row in rows[:100]
    )
    if len(rows) > 100:
        items += f'<li class="muted">+{len(rows) - 100} more</li>'
    return f"""<div class="ignored-group">
  <details>
    <summary>{_e(label)} ({len(rows)})</summary>
    <ul>{items}</ul>
  </details>
</div>"""


def _onfly_sort_key(row: dict[str, Any]) -> tuple[int, int, str, str]:
    status_rank = {"confirmed": 0, "probable": 1, "possible": 2, "ignored": 3}.get(row["result"]["status"], 4)
    return (
        status_rank,
        _severity_rank(row["result"].get("severity")),
        str(row["component"].get("name") or "").lower(),
        str(row["cve"].get("id") or ""),
    )


def _box(label: str, value: Any) -> str:
    return f'<div class="box"><div class="label">{_e(label)}</div><div class="value">{value if isinstance(value, str) and value.startswith("<") else _e(value)}</div></div>'


def _render_findings_html(payload: dict[str, Any]) -> str:
    metadata = payload["metadata"]
    counts = payload["counts"]
    decision_counts = Counter(row["decision"]["status"] for row in payload["findings"])
    strength_counts = Counter(row["decision"]["evidence_strength"] for row in payload["findings"])
    component_groups = _group_findings_for_html(payload["findings"])
    rows = "\n".join(_render_component_row(group) for group in component_groups)
    if not rows:
        rows = '<tr><td colspan="7" class="empty">No findings.</td></tr>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CVEX Findings Report</title>
  <style>
    :root {{
      --bg: #0d0f12;
      --panel: #171a1f;
      --panel-2: #1f242b;
      --ink: #e8edf2;
      --muted: #99a4b2;
      --line: #303741;
      --line-soft: #252b33;
      --header: #111418;
      --accent: #41c7b9;
      --critical: #ff5c7a;
      --high: #ff7a59;
      --medium: #f7ba45;
      --low: #64d98a;
      --info: #8ab4ff;
      --warn-bg: #352319;
      --warn: #f59e6c;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 12px/1.42 Arial, Helvetica, sans-serif;
    }}
    .shell {{ padding: 18px 20px 28px; }}
    .topbar {{
      display: grid;
      grid-template-columns: minmax(260px, 1fr) auto;
      gap: 16px;
      align-items: end;
      margin-bottom: 14px;
    }}
    h1 {{ margin: 0; font-size: 22px; line-height: 1.1; letter-spacing: 0; }}
    .subtitle {{ margin-top: 5px; color: var(--muted); font-size: 12px; }}
    .meta {{
      display: grid;
      grid-template-columns: repeat(4, minmax(130px, 1fr));
      gap: 8px;
      margin-bottom: 12px;
    }}
    .meta-item, .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.24);
    }}
    .label {{ color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .04em; }}
    .value {{ margin-top: 2px; font-weight: 700; overflow-wrap: anywhere; }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(5, minmax(130px, 1fr));
      gap: 8px;
      margin-bottom: 14px;
    }}
    .metric .value {{ font-size: 18px; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 18px 46px rgba(0, 0, 0, 0.34);
    }}
    table {{ border-collapse: separate; border-spacing: 0; width: 100%; table-layout: fixed; }}
    thead th {{
      position: sticky;
      top: 0;
      z-index: 2;
      background: var(--header);
      color: var(--ink);
      padding: 8px 9px;
      text-align: left;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: .05em;
      border-bottom: 1px solid #111820;
    }}
    tbody td {{
      padding: 9px;
      border-bottom: 1px solid var(--line-soft);
      vertical-align: top;
      background: var(--panel);
    }}
    tbody tr:hover td {{ background: #1b2027; }}
    .c-component {{ width: 15%; }}
    .c-cve {{ width: 13%; }}
    .c-sev {{ width: 9%; }}
    .c-version {{ width: 14%; }}
    .c-evidence {{ width: 19%; }}
    .c-decision {{ width: 17%; }}
    .c-desc {{ width: 13%; }}
    .name {{ font-weight: 700; overflow-wrap: anywhere; }}
    .muted {{ color: var(--muted); }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; overflow-wrap: anywhere; }}
    .desc {{ max-height: 4.2em; overflow: hidden; color: #cbd5e1; }}
    .pill {{
      display: inline-flex;
      align-items: center;
      max-width: 100%;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 2px 7px;
      margin: 0 4px 4px 0;
      background: #222832;
      font-size: 10px;
      font-weight: 700;
      line-height: 1.5;
      white-space: normal;
      overflow-wrap: anywhere;
    }}
    .sev-critical {{ color: var(--critical); background: #3a1721; border-color: #783145; }}
    .sev-high {{ color: var(--high); background: #351d17; border-color: #794231; }}
    .sev-medium {{ color: var(--medium); background: #302511; border-color: #6f5520; }}
    .sev-low {{ color: var(--low); background: #14291d; border-color: #2d6844; }}
    .sev-none, .sev-unknown {{ color: var(--muted); background: #20252d; }}
    .strength-strong {{ color: var(--low); background: #14291d; border-color: #2d6844; }}
    .strength-moderate {{ color: var(--medium); background: #302511; border-color: #6f5520; }}
    .strength-weak {{ color: var(--high); background: #351d17; border-color: #794231; }}
    .decision {{ font-weight: 700; margin-bottom: 5px; }}
    .warning {{ color: var(--warn); background: var(--warn-bg); border-color: #fed7aa; overflow-wrap: anywhere; }}
    details {{ margin-top: 5px; }}
    summary {{ cursor: pointer; color: var(--accent); font-weight: 700; }}
    .detail-block {{ margin-top: 6px; padding: 7px; border: 1px solid var(--line-soft); border-radius: 6px; background: var(--panel-2); overflow-wrap: anywhere; }}
    .detail-title {{ color: var(--muted); font-weight: 700; margin-top: 6px; }}
    .compact-list {{ margin: 4px 0 0; padding-left: 15px; }}
    .compact-list li {{ margin: 2px 0; overflow-wrap: anywhere; }}
    .empty {{ text-align: center; color: var(--muted); padding: 24px; }}
    .component-row-cell {{ padding: 0; }}
    .component-summary {{ margin: 0; }}
    .component-summary > summary {{ list-style: none; }}
    .component-summary > summary::-webkit-details-marker {{ display: none; }}
    .component-row-grid {{
      display: grid;
      grid-template-columns: 15% 13% 9% 14% 19% 17% 13%;
      gap: 0;
      align-items: start;
      padding: 9px;
    }}
    .component-row-grid > div {{ min-width: 0; padding-right: 9px; overflow-wrap: anywhere; }}
    .chevron {{ color: var(--accent); font-size: 13px; margin-right: 6px; }}
    .component-summary[open] .chevron {{ display: inline-block; transform: rotate(90deg); }}
    .component-count {{ color: var(--accent); font-weight: 700; }}
    .finding-stack {{ display: grid; gap: 8px; padding: 0 9px 10px; }}
    .finding-card {{
      border: 1px solid var(--line-soft);
      border-radius: 6px;
      background: #15191f;
      padding: 9px;
      min-width: 0;
      overflow: hidden;
    }}
    .finding-head {{
      display: grid;
      grid-template-columns: minmax(130px, .8fr) minmax(120px, .7fr) minmax(180px, 1.5fr);
      gap: 8px;
      align-items: start;
      margin-bottom: 7px;
    }}
    .finding-head > div, .finding-detail-grid > div {{ min-width: 0; overflow-wrap: anywhere; }}
    .finding-detail-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(160px, 1fr));
      gap: 8px;
    }}
    .inline-list {{ margin-top: 3px; }}
    @media (max-width: 1100px) {{
      .meta, .metrics {{ grid-template-columns: repeat(2, minmax(140px, 1fr)); }}
      .panel {{ overflow-x: auto; }}
      table {{ min-width: 1100px; }}
      .finding-head, .finding-detail-grid {{ grid-template-columns: 1fr; }}
      .component-row-grid {{ grid-template-columns: 15% 13% 9% 14% 19% 17% 13%; }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <div class="topbar">
      <div>
        <h1>CVEX Findings</h1>
        <div class="subtitle">SOC triage view for local SBOM vulnerability evidence</div>
      </div>
      <div class="muted">Generated {_e(metadata["generated_at"])}</div>
    </div>
    <div class="meta">
      {_meta_item("Client", metadata["client"])}
      {_meta_item("Product", metadata["product"])}
      {_meta_item("Release", metadata["release"])}
      {_meta_item("Scan ID", metadata["scan_id"])}
    </div>
    <div class="metrics">
      {_metric("Findings", counts["findings_total"])}
      {_metric("Affected Components", counts["affected_components"])}
      {_metric("Severity", _render_count_pills(counts["severity"], "sev"))}
      {_metric("Decision", _render_count_pills(decision_counts, "decision"))}
      {_metric("Evidence", _render_count_pills(strength_counts, "strength"))}
    </div>
    <div class="panel">
      <table>
        <thead>
          <tr>
            <th class="c-component">Component</th>
            <th class="c-cve">Findings</th>
            <th class="c-sev">Risk</th>
            <th class="c-version">Versions</th>
            <th class="c-evidence">Evidence</th>
            <th class="c-decision">Decision</th>
            <th class="c-desc">Top CVEs</th>
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""


def _group_findings_for_html(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups_by_key: dict[str, dict[str, Any]] = {}
    for row in sorted(findings, key=_html_finding_sort_key):
        component = row["component"]
        key = str(component.get("id") or f"{component.get('name')}:{component.get('normalized_version') or component.get('raw_version')}")
        if key not in groups_by_key:
            groups_by_key[key] = {"component": component, "findings": []}
        groups_by_key[key]["findings"].append(row)
    groups = list(groups_by_key.values())
    groups.sort(key=_html_component_sort_key)
    return groups


def _html_component_sort_key(group: dict[str, Any]) -> tuple[int, float, str]:
    top = group["findings"][0]
    vulnerability = top["vulnerability"]
    score = vulnerability.get("score")
    numeric_score = float(score) if isinstance(score, (int, float)) else -1.0
    return (
        _severity_rank(vulnerability.get("severity")),
        -numeric_score,
        str(group["component"].get("name") or "").lower(),
    )


def _render_component_row(group: dict[str, Any]) -> str:
    component = group["component"]
    findings = group["findings"]
    top = findings[0]
    top_vulnerability = top["vulnerability"]
    severity_counts = Counter((row["vulnerability"].get("severity") or "unknown") for row in findings)
    decision_counts = Counter(row["decision"]["status"] for row in findings)
    strength_counts = Counter(row["decision"]["evidence_strength"] for row in findings)
    cves = [row["vulnerability"]["id"] for row in findings]
    top_cves = cves[:5]
    more_cves = len(cves) - len(top_cves)
    cve_html = "".join(_pill(cve, "sev-none") for cve in top_cves)
    if more_cves > 0:
        cve_html += _pill(f"+{more_cves} more", "sev-none")
    evidence_summary = _component_evidence_summary(findings)
    details = "\n".join(_render_finding_detail(row) for row in findings)
    return f"""<tr data-component-row="true">
  <td colspan="7" class="component-row-cell">
    <details class="component-summary">
      <summary>
        <div class="component-row-grid">
          <div>
            <div class="name"><span class="chevron">›</span>{_e(component["name"])}</div>
            <div class="muted mono">{_e(component["id"])}</div>
          </div>
          <div>
            <div class="component-count">{len(findings)}</div>
            <div class="muted">unique CVEs</div>
          </div>
          <div>
            {_severity_pill(top_vulnerability["severity"])}
            <div class="muted">Max score {_e(top_vulnerability["score"] if top_vulnerability["score"] is not None else "n/a")}</div>
            <div class="inline-list">{_render_count_pills(severity_counts, "sev")}</div>
          </div>
          <div>
            <div><span class="label">Raw</span><div class="mono">{_e(component["raw_version"])}</div></div>
            <div><span class="label">Normalized</span><div class="mono">{_e(component["normalized_version"])}</div></div>
          </div>
          <div>
            {_render_count_pills(evidence_summary, "evidence")}
          </div>
          <div>
            <div>{_render_count_pills(strength_counts, "strength")}</div>
            <div>{_render_count_pills(decision_counts, "decision")}</div>
          </div>
          <div>
            {cve_html}
          </div>
        </div>
      </summary>
      <div class="finding-stack">
        {details}
      </div>
    </details>
  </td>
</tr>"""


def _render_finding_detail(row: dict[str, Any]) -> str:
    component = row["component"]
    matched = row["matched"]
    vulnerability = row["vulnerability"]
    decision = row["decision"]
    warning_text = _format_warnings(matched["warnings"])
    source_text = ", ".join(vulnerability["sources"])
    advisory_text = "; ".join(vulnerability["source_advisory_ids"])
    score = vulnerability["score"] if vulnerability["score"] is not None else "n/a"
    warning_html = ""
    if warning_text:
        warning_html = f'<div class="detail-title">Warnings</div><div class="warning">{_e(warning_text)}</div>'
    description = vulnerability["description"] or ""
    return f"""<div class="finding-card">
  <div class="finding-head">
    <div>
      <div class="mono">{_e(vulnerability["id"])}</div>
      <div>{_pill(vulnerability["status"], "sev-none")}</div>
      <div class="muted">Sources: {_e(source_text)}</div>
    </div>
    <div>
      {_severity_pill(vulnerability["severity"])}
      <div class="muted">Score {_e(score)}</div>
      {_confidence_pill(matched["confidence"])}
    </div>
    <div>
      <div class="decision">{_e(decision["status"].replace("_", " "))}</div>
      {_pill(decision["evidence_strength"], f'strength-{decision["evidence_strength"]}')}
      <div>{_e(decision["reason"])}</div>
    </div>
  </div>
  <div class="finding-detail-grid">
    <div>
      <div class="detail-title">Versions</div>
      <div><span class="label">Matched</span><div class="mono">{_e('; '.join(matched["versions"]))}</div></div>
      <div><span class="label">Component</span><div class="mono">{_e(component["normalized_version"])}</div></div>
    </div>
    <div>
      <div class="detail-title">Evidence</div>
      {_evidence_pills(matched)}
      <details>
        <summary>Evidence details</summary>
        <div class="detail-block">
          <div class="detail-title">Matched identities</div>
          {_html_list(matched["identities"])}
          <div class="detail-title">Ranges and context</div>
          {_html_list(_evidence_detail_lines(matched))}
          <div class="detail-title">Advisory IDs</div>
          <div class="mono">{_e(advisory_text)}</div>
        </div>
      </details>
    </div>
    <div>
      <div class="detail-title">Decision</div>
      <details>
        <summary>Decision factors</summary>
        <div class="detail-block">
          {_html_list(decision["factors"])}
          {warning_html}
        </div>
      </details>
      <details>
        <summary>Description</summary>
        <div class="detail-block">{_e(description)}</div>
      </details>
    </div>
  </div>
</div>"""


def _component_evidence_summary(findings: list[dict[str, Any]]) -> Counter[str]:
    summary: Counter[str] = Counter()
    for row in findings:
        matched = row["matched"]
        for match_type in matched.get("match_types") or []:
            summary[match_type] += 1
        if matched.get("version_conflict"):
            summary["version_conflict"] += 1
        if matched.get("distro_candidate"):
            summary["distro_candidate"] += 1
        if matched.get("identity_inferred"):
            summary["identity_inferred"] += 1
    if not summary:
        summary["stored_match_evidence"] = len(findings)
    return summary


def _html_finding_sort_key(row: dict[str, Any]) -> tuple[int, float, str, str]:
    vulnerability = row["vulnerability"]
    severity = vulnerability.get("severity") or "unknown"
    score = vulnerability.get("score")
    numeric_score = float(score) if isinstance(score, (int, float)) else -1.0
    return (
        _severity_rank(severity),
        -numeric_score,
        str(row["component"].get("name") or "").lower(),
        str(vulnerability.get("id") or ""),
    )


def _severity_rank(severity: str | None) -> int:
    ranks = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "moderate": 2,
        "low": 3,
        "none": 4,
        "unknown": 5,
    }
    return ranks.get(str(severity or "unknown").lower(), 5)


def _meta_item(label: str, value: Any) -> str:
    return f'<div class="meta-item"><div class="label">{_e(label)}</div><div class="value">{_e(value)}</div></div>'


def _metric(label: str, value_html: Any) -> str:
    return f'<div class="metric"><div class="label">{_e(label)}</div><div class="value">{value_html}</div></div>'


def _render_count_pills(counts: dict[str, Any] | Counter[str], class_prefix: str) -> str:
    if not counts:
        return '<span class="muted">none</span>'
    rendered = []
    for key, count in sorted(counts.items(), key=lambda item: str(item[0])):
        css_class = _mapped_pill_class(class_prefix, str(key))
        rendered.append(_pill(f"{key}: {count}", css_class))
    return "".join(rendered)


def _mapped_pill_class(class_prefix: str, value: str) -> str:
    token = _class_token(value)
    if class_prefix == "sev":
        return f"sev-{token}"
    if class_prefix == "strength":
        return f"strength-{token}"
    if class_prefix == "decision":
        if "weak" in token or "inactive" in token:
            return "strength-weak"
        if "caveat" in token or "moderate" in token:
            return "strength-moderate"
        if "strong" in token:
            return "strength-strong"
    return token


def _class_token(value: str) -> str:
    token = "".join(char.lower() if char.isalnum() else "-" for char in value)
    while "--" in token:
        token = token.replace("--", "-")
    return token.strip("-") or "unknown"


def _pill(label: Any, class_name: str = "") -> str:
    class_attr = f"pill {class_name}".strip()
    return f'<span class="{_e(class_attr)}">{_e(label)}</span>'


def _severity_pill(severity: str | None) -> str:
    normalized = _class_token(severity or "unknown")
    return _pill(severity or "unknown", f"sev-{normalized}")


def _confidence_pill(confidence: str | None) -> str:
    normalized = str(confidence or "unknown").lower()
    css_class = {
        "high": "strength-strong",
        "medium": "strength-moderate",
        "low": "strength-weak",
    }.get(normalized, "sev-none")
    return _pill(f"confidence: {normalized}", css_class)


def _evidence_pills(matched: dict[str, Any]) -> str:
    pills = [_pill(match_type, "sev-none") for match_type in (matched.get("match_types") or [])[:4]]
    if matched.get("version_conflict"):
        pills.append(_pill("version conflict", "warning"))
    if matched.get("distro_candidate"):
        pills.append(_pill("distro candidate", "warning"))
    if matched.get("identity_inferred"):
        pills.append(_pill("inferred identity", "strength-moderate"))
    if not pills:
        pills.append(_pill("stored match evidence", "sev-none"))
    return "".join(pills)


def _html_list(items: list[Any], limit: int = 8) -> str:
    values = [str(item) for item in items if item]
    if not values:
        return '<div class="muted">none</div>'
    visible = values[:limit]
    rendered = "".join(f"<li>{_e(value)}</li>" for value in visible)
    if len(values) > limit:
        rendered += f'<li class="muted">+{len(values) - limit} more</li>'
    return f'<ul class="compact-list">{rendered}</ul>'


def _evidence_detail_lines(matched: dict[str, Any]) -> list[str]:
    lines = []
    detail_fields = [
        ("CPE version", matched.get("cpe_version")),
        ("Package version", matched.get("package_version")),
        ("CPE version matched", matched.get("cpe_version_matched")),
        ("Package version matched", matched.get("package_version_matched")),
        ("Ecosystem", matched.get("ecosystem")),
        ("Package", matched.get("package_name")),
        ("Inferred from", matched.get("inferred_from_repo")),
    ]
    for label, value in detail_fields:
        if value not in (None, "", False):
            lines.append(f"{label}: {value}")
    for reason in matched.get("reasons") or []:
        lines.append(f"Reason: {reason}")
    return lines


def _format_warnings(warnings: list[dict[str, Any]]) -> str:
    rendered = []
    for warning in warnings:
        code = warning.get("code", "warning")
        count = warning.get("count")
        label = f"{code} x{count}" if count and count > 1 else code
        rendered.append(f"{label}: {warning.get('message', '')}")
    return "; ".join(rendered)


def _compact_warnings(warnings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not warnings:
        return []
    counts: Counter[str] = Counter()
    first_message: dict[str, str] = {}
    for warning in warnings:
        code = warning.get("code") or "warning"
        counts[code] += 1
        first_message.setdefault(code, warning.get("message") or "")
    return [
        {
            "code": code,
            "count": count,
            "message": _warning_summary_message(code, count, first_message.get(code, "")),
        }
        for code, count in sorted(counts.items())
    ]


def _warning_summary_message(code: str, count: int, fallback: str) -> str:
    if code == "distro_context_unconfirmed":
        return f"SBOM does not prove distro origin for {count} matched OSV distro evidence row(s)."
    if code == "package_alias_used":
        return f"Matched package name was derived from trusted SBOM identity in {count} evidence row(s)."
    if code == "version_conflict":
        return f"CPE version differs from normalized package version in {count} evidence row(s)."
    return fallback


def _matched_from_summary_evidence(finding: VulnerabilityFinding, evidence: FindingEvidence | None) -> dict[str, Any]:
    matched = {
        "versions": [],
        "identities": [],
        "match_types": [],
        "confidence": finding.confidence,
        "reasons": [],
        "warnings": [],
        "version_conflict": False,
        "cpe_version": None,
        "package_version": None,
        "cpe_version_matched": False,
        "package_version_matched": False,
        "identity_inferred": False,
        "inferred_from_repo": None,
        "distro_candidate": False,
        "ecosystem": None,
        "package_name": None,
    }
    if evidence:
        _append_unique(matched["versions"], evidence.matched_version)
        _append_unique(matched["identities"], evidence.matched_identity_value)
        _append_unique(matched["match_types"], evidence.match_type)
        _append_unique(matched["reasons"], evidence.reason)
        _merge_version_match_details(matched, evidence.matched_range or {})
        matched["warnings"] = evidence.warnings or []
    return matched


def _build_match_decision(row: dict[str, Any]) -> dict[str, Any]:
    matched = row["matched"]
    vulnerability = row["vulnerability"]
    confidence = matched["confidence"]
    warning_summary = _warning_summary(matched.get("warnings") or [])
    factors = _decision_factors(matched, vulnerability, warning_summary)
    evidence_strength = _evidence_strength(confidence, matched, vulnerability)
    status = _decision_status(evidence_strength, vulnerability)
    return {
        "status": status,
        "evidence_strength": evidence_strength,
        "reason": _decision_reason(status, evidence_strength, matched, vulnerability),
        "factors": factors,
        "warning_codes": sorted(warning_summary),
        "warning_counts": warning_summary,
    }


def _evidence_strength(confidence: str, matched: dict[str, Any], vulnerability: dict[str, Any]) -> str:
    if vulnerability.get("inactive"):
        return "weak"
    if confidence == "high" and not matched.get("version_conflict") and not matched.get("distro_candidate"):
        return "strong"
    if confidence == "high":
        return "moderate"
    if confidence == "medium":
        return "moderate"
    return "weak"


def _decision_status(evidence_strength: str, vulnerability: dict[str, Any]) -> str:
    if vulnerability.get("inactive"):
        return "matched_inactive"
    if evidence_strength == "strong":
        return "matched_strong_evidence"
    if evidence_strength == "moderate":
        return "matched_with_caveats"
    return "matched_weak_evidence"


def _decision_reason(status: str, evidence_strength: str, matched: dict[str, Any], vulnerability: dict[str, Any]) -> str:
    if status == "matched_inactive":
        return "Matched evidence exists, but the vulnerability is inactive/rejected/withdrawn and should not be counted as active risk."
    caveats = []
    if matched.get("version_conflict"):
        caveats.append("the SBOM CPE version disagrees with the normalized package version")
    if matched.get("distro_candidate"):
        caveats.append("the OSV distro package context is not proven by the SBOM")
    if matched.get("identity_inferred"):
        caveats.append("at least one identity was derived from trusted metadata rather than stated directly")
    if matched.get("warnings"):
        caveats.append("warnings are attached to the evidence")
    if evidence_strength == "strong":
        return "Matched with strong evidence: direct identity and version evidence support the affected range."
    if caveats:
        return f"Matched with moderate evidence because {', and '.join(caveats)}."
    return "Matched with moderate evidence: the affected range matched, but the evidence is not strong enough to mark as direct confirmed impact."


def _decision_factors(matched: dict[str, Any], vulnerability: dict[str, Any], warning_summary: dict[str, int]) -> list[str]:
    factors: list[str] = []
    match_types = set(matched.get("match_types") or [])
    if "cpe_and_package_version" in match_types:
        factors.append("SBOM CPE and normalized package version both matched the affected CPE range.")
    if "cpe_version" in match_types:
        factors.append("The affected range matched the version embedded in the SBOM CPE.")
    if "package_version" in match_types:
        factors.append("The affected range matched the normalized package version.")
    if "cpe_only" in match_types:
        factors.append("The source matched the CPE identity without a version-specific affected range.")
    if "inferred_cpe" in match_types:
        factors.append("A CPE was inferred from an approved repository-to-CPE alias.")
    if "osv_package_candidate" in match_types:
        factors.append("OSV package name and component version matched an affected package range.")
    if "osv_package_alias_candidate" in match_types:
        factors.append("OSV package name was derived from trusted SBOM identity and the component version matched.")
    if matched.get("version_conflict"):
        factors.append("CPE version and normalized package version differ, so confidence is limited unless both versions match.")
    if matched.get("distro_candidate"):
        factors.append("Distro package match is a candidate because the SBOM does not prove distro origin.")
    if matched.get("identity_inferred"):
        factors.append("At least one matched identity was inferred from trusted metadata.")
    for code, count in sorted(warning_summary.items()):
        label = code.replace("_", " ")
        if count == 1:
            factors.append(f"Evidence includes warning: {label}.")
        else:
            factors.append(f"Evidence includes {count} warnings of type: {label}.")
    if vulnerability.get("inactive"):
        factors.append("Vulnerability status is inactive/rejected/withdrawn.")
    if not factors:
        factors.append("Stored matcher evidence produced this finding, but no detailed evidence factor was available.")
    return _dedupe_preserve_order(factors)


def _warning_summary(warnings: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for warning in warnings:
        counts[warning.get("code") or "warning"] += 1
    return dict(counts)


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _merge_version_match_details(matched: dict[str, Any], matched_range: dict[str, Any]) -> None:
    if not matched_range:
        return
    matched["version_conflict"] = matched["version_conflict"] or bool(matched_range.get("version_conflict"))
    matched["cpe_version"] = matched["cpe_version"] or matched_range.get("cpe_version")
    matched["package_version"] = matched["package_version"] or matched_range.get("package_version")
    matched["cpe_version_matched"] = matched["cpe_version_matched"] or bool(matched_range.get("cpe_version_matched"))
    matched["package_version_matched"] = matched["package_version_matched"] or bool(matched_range.get("package_version_matched"))
    matched["identity_inferred"] = matched["identity_inferred"] or bool(matched_range.get("identity_inferred"))
    matched["inferred_from_repo"] = matched["inferred_from_repo"] or matched_range.get("inferred_from_repo")
    matched["distro_candidate"] = matched["distro_candidate"] or bool(matched_range.get("distro_candidate"))
    matched["ecosystem"] = matched["ecosystem"] or matched_range.get("ecosystem")
    matched["package_name"] = matched["package_name"] or matched_range.get("package_name")


def _top_level_warnings(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    warnings = []
    for source, state in snapshot.items():
        if state.get("health") in ("stale", "failed"):
            warnings.append(
                {
                    "code": "source_not_fresh",
                    "message": f"{source} health is {state.get('health')}. Results use available local data.",
                }
            )
    return warnings
