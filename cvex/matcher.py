from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from cvex.config import CvexConfig
from cvex.cpe import parse_cpe, same_product
from cvex.db.models import (
    ComponentIdentity,
    ConnectorState,
    FindingEvidence,
    AffectedCpe,
    SbomComponent,
    Scan,
    ScanComponentResult,
    SourcePayload,
    SourceAffectedComponent,
    SourceRun,
    VulnerabilitySeverity,
    Vulnerability,
    VulnerabilityFinding,
)
from cvex.identity import enrich_sbom_identities, inferred_cpe_source
from cvex.time import utcnow
from cvex.util import severity_label
from cvex.versioning import in_range


def run_match(
    session: Session,
    config: CvexConfig,
    sbom_id: str,
    strict_freshness: bool = False,
    sources: list[str] | None = None,
    *,
    commit: bool = True,
    progress=None,
) -> str:
    selected_sources = sources or ["nvd"]
    enrich_sbom_identities(session, config, sbom_id)
    snapshot = _source_snapshot(session, selected_sources)
    if strict_freshness:
        bad = [name for name, state in snapshot.items() if state.get("enabled") and state.get("health") in ("stale", "failed")]
        if bad:
            raise RuntimeError(f"strict freshness failed for sources: {', '.join(bad)}")

    run = SourceRun(source="matcher", run_type="match", status="running", details={"sbom_id": sbom_id})
    session.add(run)
    session.flush()
    scan = Scan(sbom_document_id=sbom_id, run_id=run.id, status="running", source_snapshot=snapshot)
    session.add(scan)
    session.flush()

    components = session.execute(
        select(SbomComponent).where(SbomComponent.sbom_document_id == sbom_id).order_by(SbomComponent.name)
    ).scalars().all()
    for index, component in enumerate(components):
        if progress:
            progress(index, len(components))
        try:
            findings = _match_component(session, scan.id, component, selected_sources)
            if findings:
                _add_component_result(
                    session,
                    scan.id,
                    component.id,
                    "matched",
                    "matched_vulnerabilities",
                    f"{len(findings)} CVE candidate(s) matched this component.",
                    _collect_component_warnings(findings),
                )
            elif component.version_status != "usable" and not _component_cpe_identities(component):
                _add_component_result(
                    session,
                    scan.id,
                    component.id,
                    "not_assessed",
                    component.version_reason or "missing_or_unusable_version",
                    "Component has no usable version or security identity for matching.",
                    [],
                )
            else:
                _add_component_result(
                    session,
                    scan.id,
                    component.id,
                    "unmatched",
                    "no_known_cve",
                    "No CVE candidates matched this component.",
                    [],
                )
        except Exception as exc:  # keep one component from stopping the scan
            _add_component_result(
                session,
                scan.id,
                component.id,
                "error",
                "matcher_error",
                str(exc),
                [{"code": "matcher_error", "message": str(exc)}],
            )

    scan.status = "succeeded"
    scan.finished_at = utcnow()
    run.status = "succeeded"
    run.finished_at = utcnow()
    if progress:
        progress(len(components), len(components))
    if commit:
        session.commit()
    else:
        session.flush()
    return str(scan.id)


def _match_component(session: Session, scan_id: str, component: SbomComponent, sources: list[str]) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    if "nvd" not in sources:
        return findings
    for identity in _component_cpe_identities(component):
        component_cpe = parse_cpe(identity.identity_value)
        if not component_cpe:
            continue
        inferred_source = inferred_cpe_source(component, identity.identity_value) if identity.identity_type == "inferred_cpe" else None
        candidates = session.execute(
            select(AffectedCpe, Vulnerability, SourcePayload)
            .join(Vulnerability, Vulnerability.cve_id == AffectedCpe.cve_id)
            .join(SourcePayload, (SourcePayload.cve_id == Vulnerability.cve_id) & (SourcePayload.source == "nvd"))
            .where(
                AffectedCpe.cpe_vendor == component_cpe.vendor,
                AffectedCpe.cpe_product == component_cpe.product,
                AffectedCpe.vulnerable.is_(True),
            )
        ).all()
        for affected, vuln, payload in candidates:
            if not affected.cpe_criteria:
                continue
            affected_cpe = parse_cpe(affected.cpe_criteria)
            if not affected_cpe or not same_product(component_cpe, affected_cpe):
                continue
            version_match = _affected_version_match(affected, component_cpe.component_version, component.normalized_version)
            if not version_match.any_matched:
                continue
            warnings = []
            if version_match.version_conflict:
                warnings.append(
                    {
                        "code": "version_conflict",
                        "message": f"CPE version {component_cpe.component_version} differs from normalized package version {component.normalized_version}.",
                    }
                )
            confidence = _cap_confidence(
                _version_confidence(component.version_status, version_match),
                _identity_max_confidence(identity.identity_type),
            )
            severity, score = _display_severity(session, vuln.cve_id)
            finding = _get_or_create_finding(session, scan_id, component.id, vuln.id, confidence, severity, score, vuln.status != "active")
            session.add(
                FindingEvidence(
                    finding_id=finding.id,
                    source="nvd",
                    match_type=_evidence_match_type(identity.identity_type, version_match),
                    matched_identity_type=identity.identity_type,
                    matched_identity_value=identity.identity_value,
                    matched_version=version_match.matched_version,
                    matched_range={
                        "source_range": affected.raw_range,
                        "version_conflict": version_match.version_conflict,
                        "cpe_version": version_match.cpe_version,
                        "package_version": version_match.package_version,
                        "cpe_version_matched": version_match.cpe_version_matched,
                        "package_version_matched": version_match.package_version_matched,
                        "identity_inferred": identity.identity_type == "inferred_cpe",
                        "inferred_from_repo": inferred_source,
                    },
                    confidence=confidence,
                    reason=_evidence_reason("nvd", identity.identity_type, inferred_source),
                    source_payload_id=payload.id,
                    warnings=warnings,
                )
            )
            findings.append(finding)
    return findings


def _match_osv_packages(session: Session, scan_id: str, component: SbomComponent) -> list[VulnerabilityFinding]:
    # Kept as a no-op import shim for downstream v1 callers. OSV has no v2 data path.
    return []


@dataclass(frozen=True)
class VersionMatch:
    cpe_version: str | None
    package_version: str | None
    cpe_version_matched: bool
    package_version_matched: bool
    version_required: bool

    @property
    def version_conflict(self) -> bool:
        return bool(self.cpe_version and self.package_version and self.cpe_version != self.package_version)

    @property
    def any_matched(self) -> bool:
        return self.cpe_version_matched or self.package_version_matched or (not self.version_required and not self.cpe_version and not self.package_version)

    @property
    def matched_version(self) -> str | None:
        matches = []
        if self.cpe_version_matched and self.cpe_version:
            matches.append(self.cpe_version)
        if self.package_version_matched and self.package_version and self.package_version not in matches:
            matches.append(self.package_version)
        if not matches and not self.version_required:
            return self.cpe_version or self.package_version
        return "; ".join(matches) if matches else None

    @property
    def match_type(self) -> str:
        if not self.cpe_version and not self.package_version:
            return "cpe_only"
        if self.cpe_version_matched and self.package_version_matched:
            return "cpe_and_package_version"
        if self.cpe_version_matched:
            return "cpe_version"
        if self.package_version_matched:
            return "package_version"
        return "cpe_only"


def _affected_version_match(affected: AffectedCpe, cpe_version: str | None, normalized_version: str | None) -> VersionMatch:
    version_required = bool(affected.version_start or affected.version_end or affected.cpe_version not in (None, "*", "-"))
    return VersionMatch(
        cpe_version=cpe_version,
        package_version=normalized_version,
        cpe_version_matched=_single_version_matches(affected, cpe_version),
        package_version_matched=_single_version_matches(affected, normalized_version),
        version_required=version_required,
    )


def _single_version_matches(affected: AffectedCpe, version: str | None) -> bool:
    if affected.version_start or affected.version_end:
        if not version:
            return False
        return in_range(version, affected.version_start, affected.start_inclusive, affected.version_end, affected.end_inclusive)
    if affected.cpe_version:
        if affected.cpe_version in ("*", "-"):
            return True
        if not version:
            return False
        return version == affected.cpe_version
    return True


def _osv_version_matches(affected: SourceAffectedComponent, version: str) -> bool:
    if affected.range_type == "osv_exact_version":
        return affected.introduced == version
    end = affected.fixed or affected.last_affected
    end_inclusive = True if affected.last_affected and not affected.fixed else False if affected.fixed else None
    return in_range(version, affected.introduced, True, end, end_inclusive)


def _version_confidence(version_status: str, version_match: VersionMatch) -> str:
    if version_status != "usable":
        return "medium"
    if not version_match.version_conflict:
        return "high"
    if version_match.cpe_version_matched and version_match.package_version_matched:
        return "high"
    return "medium"


def _get_or_create_finding(
    session: Session,
    scan_id: str,
    component_id: str,
    vulnerability_id: str,
    confidence: str,
    severity: str | None,
    score: float | None,
    inactive: bool,
) -> VulnerabilityFinding:
    existing = session.execute(
        select(VulnerabilityFinding).where(
            VulnerabilityFinding.scan_id == scan_id,
            VulnerabilityFinding.component_id == component_id,
            VulnerabilityFinding.vulnerability_id == vulnerability_id,
        )
    ).scalar_one_or_none()
    if existing:
        existing.confidence = _max_confidence(existing.confidence, confidence)
        return existing
    finding = VulnerabilityFinding(
        scan_id=scan_id,
        component_id=component_id,
        vulnerability_id=vulnerability_id,
        status="potential_risk",
        confidence=confidence,
        display_severity=severity,
        display_score=score,
        inactive=inactive,
    )
    session.add(finding)
    session.flush()
    return finding


def _add_component_result(
    session: Session,
    scan_id: str,
    component_id: str,
    status: str,
    reason_code: str,
    reason_message: str,
    warnings: list[dict[str, Any]],
) -> None:
    session.add(
        ScanComponentResult(
            scan_id=scan_id,
            component_id=component_id,
            status=status,
            reason_code=reason_code,
            reason_message=reason_message,
            warnings=warnings,
        )
    )


def _component_cpe_identities(component: SbomComponent) -> list[ComponentIdentity]:
    return [identity for identity in component.identities if identity.identity_type in ("cpe", "inferred_cpe")]


@dataclass(frozen=True)
class PackageCandidate:
    name: str
    identity_type: str
    source_value: str
    derived: bool = False


def _component_package_candidates(component: SbomComponent) -> list[PackageCandidate]:
    candidates = [
        PackageCandidate(component.name.lower(), "component_name", component.name),
    ]
    for identity in component.identities:
        if identity.identity_type in ("package_name", "upstream_package_name") and identity.identity_value:
            candidates.append(PackageCandidate(identity.identity_value.lower(), identity.identity_type, identity.identity_value))
        if identity.identity_type in ("cpe", "inferred_cpe") and identity.identity_value:
            cpe = parse_cpe(identity.identity_value)
            if cpe and cpe.product not in ("*", "-"):
                candidates.append(PackageCandidate(cpe.product.lower(), "cpe_product", identity.identity_value, derived=True))
        if identity.identity_type in ("repo_url", "upstream_repo_url") and identity.identity_value:
            repo_slug = _repo_slug(identity.identity_value)
            if repo_slug:
                candidates.append(PackageCandidate(repo_slug.lower(), "repo_slug", identity.identity_value, derived=True))
    return _dedupe_package_candidates(candidates)


def _component_package_names(component: SbomComponent) -> set[str]:
    return {candidate.name for candidate in _component_package_candidates(component)}


def _dedupe_package_candidates(candidates: list[PackageCandidate]) -> list[PackageCandidate]:
    best: dict[str, PackageCandidate] = {}
    for candidate in candidates:
        existing = best.get(candidate.name)
        if existing is None or _package_candidate_rank(candidate) > _package_candidate_rank(existing):
            best[candidate.name] = candidate
    return list(best.values())


def _best_package_candidate(candidates: list[PackageCandidate]) -> PackageCandidate | None:
    if not candidates:
        return None
    return max(candidates, key=_package_candidate_rank)


def _package_candidate_rank(candidate: PackageCandidate) -> int:
    ranks = {
        "package_name": 50,
        "upstream_package_name": 45,
        "component_name": 40,
        "cpe_product": 30,
        "repo_slug": 20,
    }
    return ranks.get(candidate.identity_type, 0)


def _repo_slug(value: str) -> str | None:
    candidate = value.strip()
    if candidate.startswith("Organization:"):
        candidate = candidate.split(":", 1)[1].strip()
    if candidate in ("NONE", "NOASSERTION"):
        return None
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = [part for part in path.split("/") if part]
    if len(parts) < 2:
        return None
    return parts[1]


def _osv_package_reason(ecosystem: str | None, package_candidate: PackageCandidate | None) -> str:
    if package_candidate and package_candidate.derived:
        return (
            f"OSV package advisory matched package/version in ecosystem {ecosystem} using "
            f"{package_candidate.identity_type} derived from SBOM identity {package_candidate.source_value}. "
            "Distro context is not confirmed by this SBOM."
        )
    return f"OSV package advisory matched package name/version in ecosystem {ecosystem}. Distro context is not confirmed by this SBOM."


def _is_cve_identifier(identifier: str | None) -> bool:
    return bool(identifier and identifier.startswith("CVE-"))


def _allow_osv_package_candidate_match(osv_ecosystem: str | None, declared_ecosystems: set[str]) -> bool:
    if not declared_ecosystems:
        return True
    if not _is_osv_distro_ecosystem(osv_ecosystem):
        return True
    return bool(declared_ecosystems & {"alpine", "debian", "ubuntu"})


def _allow_unconfirmed_osv_distro_range(affected: SourceAffectedComponent, declared_ecosystems: set[str]) -> bool:
    if not _is_osv_distro_ecosystem(affected.ecosystem):
        return True
    if declared_ecosystems & {"alpine", "debian", "ubuntu"}:
        return True
    if affected.range_type == "osv_exact_version":
        return True
    return bool(affected.fixed or affected.last_affected)


def _is_osv_distro_ecosystem(ecosystem: str | None) -> bool:
    if not ecosystem:
        return False
    normalized = ecosystem.lower()
    return normalized.startswith(("alpine:", "debian:", "ubuntu:"))


def _component_declared_package_ecosystems(component: SbomComponent) -> set[str]:
    values = [component.download_location, component.supplier]
    values.extend(identity.identity_value for identity in component.identities)
    ecosystems: set[str] = set()
    for value in values:
        ecosystems.update(_package_ecosystems_from_value(value))
    return ecosystems


def _package_ecosystems_from_value(value: str | None) -> set[str]:
    if not value:
        return set()
    normalized = value.strip().lower()
    if normalized.startswith("organization:"):
        normalized = normalized.split(":", 1)[1].strip()
    ecosystems: set[str] = set()
    if "static.crates.io/crates/" in normalized or "crates.io/crates/" in normalized or normalized.startswith("pkg:cargo/"):
        ecosystems.add("cargo")
    if "registry.npmjs.org/" in normalized or "npmjs.com/package/" in normalized or normalized.startswith("pkg:npm/"):
        ecosystems.add("npm")
    if "pypi.org/project/" in normalized or "files.pythonhosted.org/" in normalized or normalized.startswith("pkg:pypi/"):
        ecosystems.add("pypi")
    if "repo.maven.apache.org/" in normalized or "search.maven.org/" in normalized or normalized.startswith("pkg:maven/"):
        ecosystems.add("maven")
    if "pkg.go.dev/" in normalized or normalized.startswith("pkg:golang/"):
        ecosystems.add("golang")
    if "nuget.org/packages/" in normalized or normalized.startswith("pkg:nuget/"):
        ecosystems.add("nuget")
    if "packagist.org/packages/" in normalized or normalized.startswith("pkg:composer/"):
        ecosystems.add("composer")
    if "rubygems.org/gems/" in normalized or normalized.startswith("pkg:gem/"):
        ecosystems.add("gem")
    if "hex.pm/packages/" in normalized or normalized.startswith("pkg:hex/"):
        ecosystems.add("hex")
    if normalized.startswith("pkg:deb/"):
        ecosystems.add("debian")
    if normalized.startswith("pkg:apk/"):
        ecosystems.add("alpine")
    if normalized.startswith("pkg:rpm/"):
        ecosystems.add("rpm")
    return ecosystems


def _display_severity(session: Session, cve_id: str) -> tuple[str | None, float | None]:
    severities = session.execute(
        select(VulnerabilitySeverity).where(VulnerabilitySeverity.cve_id == cve_id)
    ).scalars().all()
    scores = [s.score for s in severities if s.score is not None]
    if not scores:
        return None, None
    score = max(scores)
    return severity_label(score), score


def _display_severity_for_primary_id(session: Session, primary_id: str) -> tuple[str | None, float | None]:
    severities = session.execute(
        select(VulnerabilitySeverity).where(VulnerabilitySeverity.cve_id == primary_id)
    ).scalars().all()
    scores = [s.score for s in severities if s.score is not None]
    if not scores:
        return None, None
    score = max(scores)
    return severity_label(score), score


def _max_confidence(left: str, right: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return left if order[left] >= order[right] else right


def _cap_confidence(confidence: str, cap: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return confidence if order[confidence] <= order[cap] else cap


def _identity_max_confidence(identity_type: str) -> str:
    return "medium" if identity_type == "inferred_cpe" else "high"


def _evidence_match_type(identity_type: str, version_match: VersionMatch) -> str:
    if identity_type == "inferred_cpe":
        return "inferred_cpe"
    return version_match.match_type


def _evidence_reason(source: str, identity_type: str, inferred_source: str | None) -> str:
    if identity_type == "inferred_cpe":
        if inferred_source:
            return f"Approved repo-to-CPE alias {inferred_source} matched {source.upper()} affected configuration."
        return f"Approved inferred CPE matched {source.upper()} affected configuration."
    return f"SBOM CPE matched {source.upper()} affected configuration."


def _collect_component_warnings(findings: list[VulnerabilityFinding]) -> list[dict[str, Any]]:
    # Evidence warnings are included at finding level in the summary. Component-level
    # warnings remain reserved for component-wide issues.
    return []


def _source_snapshot(session: Session, sources: list[str]) -> dict[str, Any]:
    rows = session.execute(select(ConnectorState).where(ConnectorState.source.in_(sources))).scalars().all()
    snapshot = {}
    for row in rows:
        health = row.health
        if row.last_success and row.freshness_sla_seconds and (utcnow()-row.last_success).total_seconds() > row.freshness_sla_seconds:
            health = "stale"
        snapshot[row.source] = {
            "enabled": row.enabled,
            "status": row.status,
            "health": health,
            "last_success": row.last_success.isoformat() if row.last_success else None,
            "checkpoint_type": row.checkpoint_type,
            "checkpoint_value": row.checkpoint_value,
        }
    for source in sources:
        snapshot.setdefault(source, {"enabled": True, "status": "idle", "health": "degraded", "warning": "no connector state"})
    return snapshot
