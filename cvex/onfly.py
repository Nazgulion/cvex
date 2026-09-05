from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cvex.config import CvexConfig
from cvex.cpe import parse_cpe, same_product
from cvex.db.models import (
    ComponentIdentity,
    FindingEvidence,
    Product,
    AffectedCpe,
    SbomComponent,
    SbomDocument,
    Scan,
    ScanComponentResult,
    SourcePayload,
    SourceRun,
    SourceAffectedComponent,
    SourceSeverity,
    SourceVulnerability,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilitySeverity,
)
from cvex.matcher import _affected_version_match
from cvex.time import isoformat_z, utcnow
from cvex.util import parse_dt, severity_label, sha256_bytes


SCAN_TYPE = "onfly"
HIT_STATUS_ORDER = {"confirmed": 3, "probable": 2, "possible": 1, "ignored": 0}


@dataclass(frozen=True)
class WatchlistAlias:
    value: str
    type: str
    source: str


@dataclass(frozen=True)
class WatchlistComponent:
    component_id: str
    name: str
    normalized_version: str
    raw_version: str | None
    aliases: tuple[WatchlistAlias, ...] = ()
    cpes: tuple[str, ...] = ()
    purls: tuple[str, ...] = ()
    repo_urls: tuple[str, ...] = ()
    vendor_aliases: tuple[str, ...] = ()
    product_aliases: tuple[str, ...] = ()
    baseline_cves: tuple[str, ...] = ()
    baseline_severity_by_cve: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Watchlist:
    path: str
    sha256: str
    payload: dict[str, Any]
    components: tuple[WatchlistComponent, ...]
    skipped: tuple[dict[str, Any], ...]


@dataclass
class MergedCve:
    cve_id: str
    source_vulns: list[SourceVulnerability]
    affected: list[SourceAffectedComponent]
    severities: list[tuple[str, SourceSeverity]]
    source_record_ids: list[str]
    source_modified: dict[str, str | None]

    @property
    def sources(self) -> list[str]:
        return sorted({source_vuln.source for source_vuln in self.source_vulns})

    @property
    def description(self) -> str | None:
        by_source = {source_vuln.source: source_vuln.description for source_vuln in self.source_vulns if source_vuln.description}
        return by_source.get("cve") or by_source.get("nvd") or next(iter(by_source.values()), None)


@dataclass(frozen=True)
class SourceOutcome:
    status: str
    source: str
    match_type: str
    confidence: str
    reason: str
    matched_identity_type: str | None = None
    matched_identity_value: str | None = None
    matched_version: str | None = None
    matched_range: dict[str, Any] = field(default_factory=dict)
    source_record_id: str | None = None
    warnings: tuple[dict[str, Any], ...] = ()


def run_onfly_scan(
    session: Session,
    config: CvexConfig,
    watchlist_path: str,
    since: str | None = None,
    until: str | None = None,
    source: str = "all",
) -> str:
    watchlist = load_watchlist(watchlist_path)
    selected_sources = _selected_onfly_sources(source)
    since_dt, until_dt = _resolve_window(since, until)
    changed = _changed_cves(session, selected_sources, since_dt, until_dt)
    sbom = _get_or_create_watchlist_sbom(session, watchlist)

    run = SourceRun(
        source="matcher",
        run_type="match",
        status="running",
        details={
            "scan_type": SCAN_TYPE,
            "watchlist_path": watchlist.path,
            "watchlist_sha256": watchlist.sha256,
            "since": isoformat_z(since_dt),
            "until": isoformat_z(until_dt),
            "sources": selected_sources,
        },
    )
    session.add(run)
    session.flush()

    snapshot = {
        "scan_type": SCAN_TYPE,
        "watchlist_path": watchlist.path,
        "watchlist_sha256": watchlist.sha256,
        "window": {"since": isoformat_z(since_dt), "until": isoformat_z(until_dt)},
        "sources": selected_sources,
        "payloads_considered": sum(len(cve.source_vulns) for cve in changed),
        "cves_considered": len(changed),
        "components": {
            "loaded": len(watchlist.payload.get("components") or []),
            "skipped": len(watchlist.skipped),
            "used": len(watchlist.components),
            "skip_reasons": list(watchlist.skipped),
        },
        "warnings": [],
    }
    scan = Scan(sbom_document_id=sbom.id, run_id=run.id, status="running", source_snapshot=snapshot)
    session.add(scan)
    session.flush()

    components_by_source_id = _sbom_components_by_source_id(session, sbom.id)
    comparison_counts: Counter[str] = Counter()
    for component in watchlist.components:
        db_component = components_by_source_id[component.component_id]
        component_results = []
        for cve in changed:
            result = _compare_component_to_cve(component, cve)
            comparison_counts[result.status] += 1
            _persist_onfly_result(session, scan.id, db_component.id, cve, component, result)
            component_results.append(result)
        _add_onfly_component_result(session, scan.id, db_component.id, component_results)

    final_snapshot = {**snapshot, "comparison_counts": dict(comparison_counts)}
    scan.source_snapshot = final_snapshot
    scan.status = "succeeded"
    scan.finished_at = utcnow()
    run.status = "succeeded"
    run.finished_at = utcnow()
    run.details = {**(run.details or {}), "scan_id": str(scan.id), "comparison_counts": dict(comparison_counts)}
    session.commit()
    return str(scan.id)


def load_watchlist(path: str | Path) -> Watchlist:
    watchlist_path = Path(path)
    data = watchlist_path.read_bytes()
    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"watchlist JSON is unreadable or invalid: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("watchlist JSON must be an object")
    components, skipped = _validate_components(payload.get("components"))
    if not components:
        raise ValueError("watchlist has zero usable components")
    return Watchlist(
        path=str(watchlist_path),
        sha256=sha256_bytes(data),
        payload=payload,
        components=tuple(components),
        skipped=tuple(skipped),
    )


def _validate_components(raw_components: Any) -> tuple[list[WatchlistComponent], list[dict[str, Any]]]:
    components: list[WatchlistComponent] = []
    skipped: list[dict[str, Any]] = []
    seen_component_ids: set[str] = set()
    if not isinstance(raw_components, list):
        return [], [{"index": None, "component_id": None, "reason": "components_not_list"}]
    for index, raw in enumerate(raw_components):
        if not isinstance(raw, dict):
            skipped.append({"index": index, "component_id": None, "reason": "component_not_object"})
            continue
        component_id = _string(raw.get("component_id"))
        name = _string(raw.get("name"))
        normalized_version = _string(raw.get("normalized_version"))
        if not component_id or not name:
            skipped.append({"index": index, "component_id": component_id, "reason": "missing_component_id_or_name"})
            continue
        if component_id in seen_component_ids:
            skipped.append({"index": index, "component_id": component_id, "reason": "duplicate_component_id"})
            continue
        if not normalized_version:
            skipped.append({"index": index, "component_id": component_id, "reason": "missing_normalized_version"})
            continue
        aliases = tuple(_parse_aliases(raw.get("aliases")))
        cpes = tuple(_string_list(raw.get("cpes")))
        purls = tuple(_string_list(raw.get("purls")))
        repo_urls = tuple(_string_list(raw.get("repo_urls")))
        vendor_aliases = tuple(_string_list(raw.get("vendor_aliases")))
        product_aliases = tuple(_string_list(raw.get("product_aliases")))
        if not any((aliases, cpes, purls, repo_urls, vendor_aliases, product_aliases)):
            skipped.append({"index": index, "component_id": component_id, "reason": "missing_identity_beyond_display_name"})
            continue
        seen_component_ids.add(component_id)
        baseline_cves, baseline_severity = _parse_baseline_cves(raw.get("baseline_cves"))
        components.append(
            WatchlistComponent(
                component_id=component_id,
                name=name,
                normalized_version=normalized_version,
                raw_version=_string(raw.get("raw_version")),
                aliases=aliases,
                cpes=cpes,
                purls=purls,
                repo_urls=repo_urls,
                vendor_aliases=vendor_aliases,
                product_aliases=product_aliases,
                baseline_cves=tuple(baseline_cves),
                baseline_severity_by_cve=baseline_severity,
            )
        )
    return components, skipped


def _parse_aliases(value: Any) -> list[WatchlistAlias]:
    aliases: list[WatchlistAlias] = []
    if not isinstance(value, list):
        return aliases
    for item in value:
        if isinstance(item, str) and item.strip():
            aliases.append(WatchlistAlias(value=item.strip(), type="alias", source="watchlist"))
        if isinstance(item, dict) and _string(item.get("value")):
            aliases.append(
                WatchlistAlias(
                    value=_string(item.get("value")) or "",
                    type=_string(item.get("type")) or "alias",
                    source=_string(item.get("source")) or "watchlist",
                )
            )
    return aliases


def _parse_baseline_cves(value: Any) -> tuple[list[str], dict[str, str]]:
    cves: list[str] = []
    severities: dict[str, str] = {}
    if not isinstance(value, list):
        return cves, severities
    for item in value:
        if isinstance(item, str) and item.strip():
            cves.append(item.strip())
        elif isinstance(item, dict) and _string(item.get("id")):
            cve_id = _string(item.get("id")) or ""
            cves.append(cve_id)
            if _string(item.get("severity")):
                severities[cve_id] = _string(item.get("severity")) or ""
    return cves, severities


def _compare_component_to_cve(component: WatchlistComponent, cve: MergedCve) -> SourceOutcome:
    if any(source_vuln.status != "active" for source_vuln in cve.source_vulns):
        return SourceOutcome(
            status="ignored",
            source="cve",
            match_type="cve_rejected",
            confidence="low",
            reason="CVE List status is rejected/inactive.",
            source_record_id=_source_record_id_for(cve, "cve"),
        )
    outcomes: list[SourceOutcome] = []
    if any(source_vuln.source == "nvd" for source_vuln in cve.source_vulns):
        outcomes.append(_compare_nvd(component, cve))
    if any(source_vuln.source == "cve" for source_vuln in cve.source_vulns):
        outcomes.append(_compare_cve_text(component, cve))
    outcomes = [outcome for outcome in outcomes if outcome is not None]
    if not outcomes:
        return SourceOutcome(
            status="ignored",
            source="merged",
            match_type="no_evidence",
            confidence="low",
            reason="No normalized source evidence was available for this CVE.",
        )
    return max(outcomes, key=lambda outcome: HIT_STATUS_ORDER[outcome.status])


def _compare_nvd(component: WatchlistComponent, cve: MergedCve) -> SourceOutcome:
    best_ignored: SourceOutcome | None = None
    component_cpes = [parse_cpe(cpe) for cpe in component.cpes]
    component_cpes = [cpe for cpe in component_cpes if cpe]
    for affected in cve.affected:
        if affected.vulnerable is not True:
            continue
        affected_cpe = parse_cpe(affected.cpe_criteria or affected.cpe)
        cpe_identity_seen = False
        if affected_cpe:
            for component_cpe in component_cpes:
                if not same_product(component_cpe, affected_cpe):
                    continue
                cpe_identity_seen = True
                version_match = _affected_version_match(affected, component_cpe.component_version, component.normalized_version)
                if version_match.any_matched:
                    return SourceOutcome(
                        status="confirmed",
                        source="nvd",
                        match_type=version_match.match_type,
                        confidence="high",
                        reason="NVD CPE identity and affected version matched watchlist component.",
                        matched_identity_type="cpe",
                        matched_identity_value=component_cpe.raw,
                        matched_version=version_match.matched_version,
                        matched_range={
                            "source_range": affected.raw_range,
                            "version_conflict": version_match.version_conflict,
                            "cpe_version": version_match.cpe_version,
                            "package_version": version_match.package_version,
                            "cpe_version_matched": version_match.cpe_version_matched,
                            "package_version_matched": version_match.package_version_matched,
                            "severity_source": _severity_source(cve, component),
                        },
                        source_record_id=_source_record_id_for(cve, "nvd"),
                    )
                if _version_cannot_be_decided(affected, component_cpe.component_version, component.normalized_version):
                    return SourceOutcome(
                        status="probable",
                        source="nvd",
                        match_type="cpe_version_unknown",
                        confidence="medium",
                        reason="NVD CPE identity matched, but affected version could not be decided.",
                        matched_identity_type="cpe",
                        matched_identity_value=component_cpe.raw,
                        matched_version=component.normalized_version,
                        matched_range={"source_range": affected.raw_range, "severity_source": _severity_source(cve, component)},
                        source_record_id=_source_record_id_for(cve, "nvd"),
                    )
                best_ignored = SourceOutcome(
                    status="ignored",
                    source="nvd",
                    match_type="cpe_version_not_affected",
                    confidence="low",
                    reason="NVD CPE identity matched, but watchlist component version is not affected.",
                    matched_identity_type="cpe",
                    matched_identity_value=component_cpe.raw,
                    matched_version=component.normalized_version,
                    matched_range={"source_range": affected.raw_range, "severity_source": _severity_source(cve, component)},
                    source_record_id=_source_record_id_for(cve, "nvd"),
                )
        if not cpe_identity_seen and _weak_nvd_name_match(component, affected):
            return SourceOutcome(
                status="possible",
                source="nvd",
                match_type="nvd_weak_name",
                confidence="low",
                reason="NVD affected CPE product matched a trusted watchlist name or alias without usable CPE identity.",
                matched_identity_type="product_name",
                matched_identity_value=affected.cpe_product,
                matched_version=component.normalized_version,
                matched_range={"source_range": affected.raw_range, "severity_source": _severity_source(cve, component)},
                source_record_id=_source_record_id_for(cve, "nvd"),
            )
    return best_ignored or SourceOutcome(
        status="ignored",
        source="nvd",
        match_type="nvd_no_identity_match",
        confidence="low",
        reason="NVD affected identities did not match the watchlist component.",
        source_record_id=_source_record_id_for(cve, "nvd"),
        matched_range={"severity_source": _severity_source(cve, component)},
    )


def _compare_cve_text(component: WatchlistComponent, cve: MergedCve) -> SourceOutcome:
    text = cve.description or ""
    for term, source in _trusted_text_terms(component):
        if _token_match(term, text):
            return SourceOutcome(
                status="possible",
                source="cve",
                match_type="cve_text_alias",
                confidence="low",
                reason=f"CVE List text matched {source} {term}.",
                matched_identity_type=source,
                matched_identity_value=term,
                matched_version=component.normalized_version,
                matched_range={"severity_source": _severity_source(cve, component)},
                source_record_id=_source_record_id_for(cve, "cve"),
            )
    return SourceOutcome(
        status="ignored",
        source="cve",
        match_type="cve_text_no_match",
        confidence="low",
        reason="CVE List text did not match component name or trusted aliases.",
        source_record_id=_source_record_id_for(cve, "cve"),
        matched_range={"severity_source": _severity_source(cve, component)},
    )


def _persist_onfly_result(
    session: Session,
    scan_id: str,
    component_id: str,
    cve: MergedCve,
    component: WatchlistComponent,
    outcome: SourceOutcome,
) -> None:
    vuln = _get_or_create_canonical_vulnerability(session, cve)
    severity, score, severity_source = _display_severity(cve, component)
    label = "known_cve_update" if cve.cve_id in set(component.baseline_cves) else "new_hit"
    finding = VulnerabilityFinding(
        scan_id=scan_id,
        component_id=component_id,
        vulnerability_id=vuln.id,
        status=outcome.status,
        confidence=outcome.confidence,
        display_severity=severity,
        display_score=score,
        inactive=outcome.status == "ignored",
    )
    session.add(finding)
    session.flush()
    matched_range = {
        **outcome.matched_range,
        "delta_label": label,
        "severity_source": severity_source,
        "sources": cve.sources,
        "source_modified": cve.source_modified,
        "onfly_status": outcome.status,
    }
    session.add(
        FindingEvidence(
            finding_id=finding.id,
            source=outcome.source,
            match_type=outcome.match_type,
            matched_identity_type=outcome.matched_identity_type,
            matched_identity_value=outcome.matched_identity_value,
            matched_version=outcome.matched_version,
            matched_range=matched_range,
            confidence=outcome.confidence,
            reason=outcome.reason,
            source_payload_id=outcome.source_record_id,
            warnings=list(outcome.warnings),
        )
    )


def _changed_cves(session: Session, sources: list[str], since, until) -> list[MergedCve]:
    payload_rows = session.execute(
        select(SourcePayload)
        .where(
            SourcePayload.source.in_(sources),
            SourcePayload.source_modified.is_not(None),
            SourcePayload.source_modified >= since,
            SourcePayload.source_modified <= until,
        )
        .order_by(SourcePayload.source, SourcePayload.cve_id)
    ).scalars().all()
    if not payload_rows:
        return []
    cve_ids = sorted({row.cve_id for row in payload_rows})
    # The window chooses CVE IDs; comparisons use both current source payloads
    # so CVE List precedence still applies when only the NVD payload changed.
    payload_rows = session.execute(
        select(SourcePayload)
        .where(SourcePayload.source.in_(sources), SourcePayload.cve_id.in_(cve_ids))
        .order_by(SourcePayload.source, SourcePayload.cve_id)
    ).scalars().all()
    vulnerabilities = {row.cve_id: row for row in session.execute(select(Vulnerability).where(Vulnerability.cve_id.in_(cve_ids))).scalars()}
    affected_by_cve = _affected_by_cve(session, cve_ids)
    severities_by_cve = _severities_by_cve(session, cve_ids)
    by_cve: dict[str, list[SourcePayload]] = defaultdict(list)
    for payload in payload_rows:
        by_cve[payload.cve_id].append(payload)
    merged = []
    for cve_id, rows in by_cve.items():
        vuln = vulnerabilities[cve_id]
        source_vulns = [SourceVulnerability(source=row.source, primary_id=cve_id, status=vuln.status, description=vuln.description, source_record_id=row.id, published=vuln.published, modified=vuln.modified, withdrawn=vuln.withdrawn) for row in rows]
        severities = [("nvd", severity) for severity in severities_by_cve.get(cve_id, [])]
        merged.append(MergedCve(cve_id, source_vulns, affected_by_cve.get(cve_id, []), severities, [str(row.id) for row in rows], {row.source: isoformat_z(row.source_modified) for row in rows}))
    return merged


def _affected_by_cve(session: Session, cve_ids: list[str]) -> dict[str, list[AffectedCpe]]:
    if not cve_ids:
        return {}
    rows = session.execute(select(AffectedCpe).where(AffectedCpe.cve_id.in_(cve_ids))).scalars().all()
    grouped: dict[str, list[AffectedCpe]] = defaultdict(list)
    for row in rows:
        grouped[row.cve_id].append(row)
    return grouped


def _severities_by_cve(session: Session, cve_ids: list[str]) -> dict[str, list[VulnerabilitySeverity]]:
    if not cve_ids:
        return {}
    rows = session.execute(select(VulnerabilitySeverity).where(VulnerabilitySeverity.cve_id.in_(cve_ids))).scalars().all()
    grouped: dict[str, list[VulnerabilitySeverity]] = defaultdict(list)
    for row in rows:
        grouped[row.cve_id].append(row)
    return grouped


def _get_or_create_watchlist_sbom(session: Session, watchlist: Watchlist) -> SbomDocument:
    existing = session.execute(select(SbomDocument).where(SbomDocument.content_sha256 == watchlist.sha256)).scalar_one_or_none()
    if existing:
        return existing
    product = _get_or_create_product(
        session,
        watchlist.payload.get("client") or "watchlist",
        watchlist.payload.get("product") or "onfly",
        watchlist.payload.get("release") or watchlist.sha256[:12],
    )
    run = SourceRun(source="sbom", run_type="import", status="running", details={"scan_type": SCAN_TYPE, "watchlist_path": watchlist.path})
    session.add(run)
    session.flush()
    doc = SbomDocument(
        product_id=product.id,
        format="cvex-watchlist",
        format_version=watchlist.payload.get("schema_version"),
        content_sha256=watchlist.sha256,
        name=f"{watchlist.payload.get('product') or 'onfly'} watchlist",
        document_namespace=watchlist.path,
        created_by="cvex onfly",
        created_at_source=parse_dt(watchlist.payload.get("baseline_generated_at")),
        raw_payload={"schema_version": watchlist.payload.get("schema_version"), "sbom_sha256": watchlist.payload.get("sbom_sha256")},
        run_id=run.id,
    )
    session.add(doc)
    session.flush()
    for component in watchlist.components:
        db_component = SbomComponent(
            sbom_document_id=doc.id,
            source_component_id=component.component_id,
            component_kind="watchlist",
            name=component.name,
            raw_version=component.raw_version,
            normalized_version=component.normalized_version,
            version_status="usable",
        )
        session.add(db_component)
        session.flush()
        _add_identity(db_component, "package_name", component.name)
        for alias in component.aliases:
            _add_identity(db_component, alias.type, alias.value)
        for cpe in component.cpes:
            _add_identity(db_component, "cpe", cpe)
        for purl in component.purls:
            _add_identity(db_component, "purl", purl)
        for repo_url in component.repo_urls:
            _add_identity(db_component, "repo_url", repo_url)
        for vendor in component.vendor_aliases:
            _add_identity(db_component, "vendor_alias", vendor)
        for product_name in component.product_aliases:
            _add_identity(db_component, "product_alias", product_name)
    run.status = "succeeded"
    run.finished_at = utcnow()
    return doc


def _get_or_create_product(session: Session, client: str, product: str, release: str) -> Product:
    existing = session.execute(
        select(Product).where(Product.client_name == client, Product.product_name == product, Product.release_version == release)
    ).scalar_one_or_none()
    if existing:
        return existing
    row = Product(client_name=client, product_name=product, release_version=release)
    session.add(row)
    session.flush()
    return row


def _add_identity(component: SbomComponent, identity_type: str, value: str) -> None:
    if value and not any(identity.identity_type == identity_type and identity.identity_value == value for identity in component.identities):
        component.identities.append(ComponentIdentity(identity_type=identity_type, identity_value=value))


def _sbom_components_by_source_id(session: Session, sbom_id: str) -> dict[str, SbomComponent]:
    rows = session.execute(select(SbomComponent).where(SbomComponent.sbom_document_id == sbom_id)).scalars().all()
    return {row.source_component_id: row for row in rows}


def _add_onfly_component_result(session: Session, scan_id: str, component_id: str, results: list[SourceOutcome]) -> None:
    counts = Counter(result.status for result in results)
    hit_count = counts["confirmed"] + counts["probable"] + counts["possible"]
    status = "matched" if hit_count else "unmatched"
    reason_code = "onfly_hits" if hit_count else "onfly_no_hits"
    reason_message = f"{hit_count} on-fly hit(s), {counts['ignored']} ignored comparison(s)."
    session.add(
        ScanComponentResult(
            scan_id=scan_id,
            component_id=component_id,
            status=status,
            reason_code=reason_code,
            reason_message=reason_message,
            warnings=[],
        )
    )


def _get_or_create_canonical_vulnerability(session: Session, cve: MergedCve) -> Vulnerability:
    existing = session.execute(select(Vulnerability).where(Vulnerability.cve_id == cve.cve_id)).scalar_one_or_none()
    if existing:
        return existing
    first = cve.source_vulns[0]
    vuln = Vulnerability(
        cve_id=cve.cve_id,
        published=first.published,
        modified=first.modified,
        withdrawn=first.withdrawn,
        status="inactive" if any(source_vuln.status != "active" for source_vuln in cve.source_vulns) else "active",
    )
    session.add(vuln)
    session.flush()
    return vuln


def _display_severity(cve: MergedCve, component: WatchlistComponent) -> tuple[str | None, float | None, str]:
    nvd_scores = [severity.score for source, severity in cve.severities if source == "nvd" and severity.score is not None]
    if nvd_scores:
        score = max(nvd_scores)
        return severity_label(score), score, "nvd"
    cve_scores = [severity.score for source, severity in cve.severities if source == "cve" and severity.score is not None]
    if cve_scores:
        score = max(cve_scores)
        return severity_label(score), score, "cve"
    if cve.cve_id in component.baseline_cves and component.baseline_severity_by_cve.get(cve.cve_id):
        return component.baseline_severity_by_cve[cve.cve_id], None, "ai_baseline"
    return "unknown", None, "unknown"


def _severity_source(cve: MergedCve, component: WatchlistComponent) -> str:
    return _display_severity(cve, component)[2]


def _source_record_id_for(cve: MergedCve, source: str) -> str | None:
    for source_vuln in cve.source_vulns:
        if source_vuln.source == source:
            return str(source_vuln.source_record_id)
    return None


def _trusted_text_terms(component: WatchlistComponent) -> list[tuple[str, str]]:
    terms = [(component.name, "component name")]
    terms.extend((alias.value, f"trusted AI alias") for alias in component.aliases)
    return [(term, source) for term, source in terms if term]


def _token_match(term: str, text: str) -> bool:
    pattern = rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])"
    return bool(re.search(pattern, text, flags=re.IGNORECASE))


def _weak_nvd_name_match(component: WatchlistComponent, affected: SourceAffectedComponent) -> bool:
    product = (affected.cpe_product or "").lower()
    if not product:
        return False
    names = {component.name.lower()}
    names.update(alias.value.lower() for alias in component.aliases)
    names.update(value.lower() for value in component.product_aliases)
    return product in names


def _version_cannot_be_decided(affected: SourceAffectedComponent, cpe_version: str | None, package_version: str | None) -> bool:
    version_required = bool(affected.version_start or affected.version_end or affected.cpe_version not in (None, "*", "-"))
    return version_required and not cpe_version and not package_version


def _resolve_window(since: str | None, until: str | None):
    until_dt = parse_dt(until) if until else utcnow()
    since_dt = parse_dt(since) if since else until_dt - timedelta(hours=24)
    if since_dt is None or until_dt is None:
        raise ValueError("since/until could not be parsed")
    if since_dt > until_dt:
        raise ValueError("--since must be before --until")
    return since_dt, until_dt


def _selected_onfly_sources(source: str) -> list[str]:
    if source == "all":
        return ["cve", "nvd"]
    if source not in ("cve", "nvd"):
        raise ValueError(f"unknown on-fly source: {source}")
    return [source]


def _string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := _string(item))]
