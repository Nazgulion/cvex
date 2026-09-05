from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from cvex.config import CvexConfig, IdentityAliasConfig
from cvex.db.models import ComponentIdentity, SbomComponent, SbomDocument
from cvex.versioning import normalize_version


TRUSTED_OVERRIDE_VERSION_RE = re.compile(r"^\d+(?:[._-]\d+)*$")


@dataclass(frozen=True)
class RepoAliasMatch:
    alias_key: str
    repo_url: str
    cpe: str


def enrich_sbom_identities(session: Session, config: CvexConfig, sbom_id: str) -> int:
    sbom = session.execute(select(SbomDocument).where(SbomDocument.id == sbom_id)).scalar_one()
    packages_by_id = {pkg["SPDXID"]: pkg for pkg in sbom.raw_payload.get("packages", []) if pkg.get("SPDXID")}
    variant_map = {
        rel.get("spdxElementId"): rel.get("relatedSpdxElement")
        for rel in sbom.raw_payload.get("relationships", [])
        if rel.get("relationshipType") == "VARIANT_OF"
    }
    components = session.execute(select(SbomComponent).where(SbomComponent.sbom_document_id == sbom_id)).scalars().all()
    changed = 0

    for component in components:
        pkg = packages_by_id.get(component.source_component_id)
        upstream_pkg = packages_by_id.get(variant_map.get(component.source_component_id) or "")
        if not pkg:
            continue
        changed += _apply_version_override(session, config, component)

        if upstream_pkg:
            upstream_download = upstream_pkg.get("downloadLocation")
            upstream_supplier = upstream_pkg.get("supplier")
            if _usable_url(upstream_download):
                changed += _add_identity(session, component, "upstream_repo_url", normalize_repo_url(upstream_download) or upstream_download)
                if component.download_location in (None, "", "NONE", "NOASSERTION"):
                    component.download_location = upstream_download
            if upstream_supplier and component.supplier in (None, "", "NOASSERTION"):
                component.supplier = upstream_supplier

        for identity_type, repo_value in _component_repo_values(pkg, upstream_pkg):
            normalized_repo = normalize_repo_url(repo_value)
            if not normalized_repo:
                continue
            changed += _add_identity(session, component, identity_type, normalized_repo)
            alias_match = infer_cpe_from_repo(config, normalized_repo, component.normalized_version)
            if alias_match:
                changed += _add_identity(session, component, "inferred_cpe", alias_match.cpe)
                changed += _add_identity(session, component, "inferred_cpe_source", f"{alias_match.alias_key} -> {alias_match.cpe}")

    if changed:
        session.flush()
    return changed


def infer_cpe_from_repo(config: CvexConfig, repo_url: str, version: str | None) -> RepoAliasMatch | None:
    normalized_repo = normalize_repo_url(repo_url)
    if not normalized_repo:
        return None
    alias = _alias_for_repo(config, normalized_repo)
    if not alias:
        return None
    return RepoAliasMatch(
        alias_key=normalized_repo,
        repo_url=normalized_repo,
        cpe=_build_cpe(alias, version),
    )


def normalize_repo_url(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if candidate.startswith("Organization:"):
        candidate = candidate.split(":", 1)[1].strip()
    if candidate in ("NONE", "NOASSERTION"):
        return None
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    host = (parsed.netloc or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    path_parts = [part for part in path.split("/") if part]
    if host != "github.com" or len(path_parts) < 2:
        return None
    return f"{host}/{path_parts[0].lower()}/{path_parts[1].lower()}"


def inferred_cpe_source(component: SbomComponent, cpe_value: str) -> str | None:
    suffix = f" -> {cpe_value}"
    for identity in component.identities:
        if identity.identity_type == "inferred_cpe_source" and identity.identity_value.endswith(suffix):
            return identity.identity_value.removesuffix(suffix)
    return None


def _component_repo_values(pkg: dict, upstream_pkg: dict | None) -> list[tuple[str, str]]:
    values = []
    if _usable_url(pkg.get("downloadLocation")):
        values.append(("repo_url", pkg["downloadLocation"]))
    if _usable_url(pkg.get("supplier")):
        values.append(("repo_url", pkg["supplier"]))
    if upstream_pkg:
        if _usable_url(upstream_pkg.get("downloadLocation")):
            values.append(("upstream_repo_url", upstream_pkg["downloadLocation"]))
        if _usable_url(upstream_pkg.get("supplier")):
            values.append(("upstream_repo_url", upstream_pkg["supplier"]))
    return values


def _alias_for_repo(config: CvexConfig, normalized_repo: str) -> IdentityAliasConfig | None:
    aliases = {normalize_repo_url(key): value for key, value in config.identity_aliases.items()}
    return aliases.get(normalized_repo)


def _build_cpe(alias: IdentityAliasConfig, version: str | None) -> str:
    cpe_version = version or "*"
    return f"cpe:2.3:{alias.cpe_part}:{alias.cpe_vendor}:{alias.cpe_product}:{cpe_version}:*:*:*:*:*:*:*"


def _add_identity(session: Session | None, component: SbomComponent, identity_type: str, identity_value: str) -> int:
    for existing in component.identities:
        if existing.identity_type == identity_type and existing.identity_value == identity_value:
            return 0
    if session is None:
        component.identities.append(ComponentIdentity(identity_type=identity_type, identity_value=identity_value))
        return 1
    duplicate = session.execute(
        select(ComponentIdentity).where(
            ComponentIdentity.component_id == component.id,
            ComponentIdentity.identity_type == identity_type,
            ComponentIdentity.identity_value == identity_value,
        )
    ).scalar_one_or_none()
    if duplicate:
        return 0
    component.identities.append(ComponentIdentity(identity_type=identity_type, identity_value=identity_value))
    return 1


def _apply_version_override(session: Session | None, config: CvexConfig, component: SbomComponent) -> int:
    override = _matching_version_override(config, component)
    if not override:
        return 0
    resolved_version = _trusted_override_version(override.version)
    if not resolved_version:
        return 0

    changed = 0
    if component.normalized_version != resolved_version:
        component.normalized_version = resolved_version
        changed += 1
    if component.version_status != "usable":
        component.version_status = "usable"
        changed += 1
    reason = f"version_override:{override.source}"
    if component.version_reason != reason:
        component.version_reason = reason
        changed += 1
    changed += _add_identity(session, component, "resolved_version", resolved_version)
    changed += _add_identity(session, component, "resolved_version_source", override.source)
    if override.raw_version:
        changed += _add_identity(session, component, "resolved_version_raw", override.raw_version)
    return changed


def _matching_version_override(config: CvexConfig, component: SbomComponent):
    for override in config.version_overrides:
        if override.component_name and override.component_name.lower() != component.name.lower():
            continue
        if override.source_component_id and override.source_component_id != component.source_component_id:
            continue
        if override.raw_version and override.raw_version != component.raw_version:
            continue
        if not (override.component_name or override.source_component_id or override.raw_version):
            continue
        return override
    return None


def _trusted_override_version(version: str) -> str | None:
    normalized = normalize_version(version)
    if normalized.status == "usable" and normalized.normalized:
        return normalized.normalized
    candidate = version.strip().removeprefix("v").replace("_", ".").replace("-", ".")
    if TRUSTED_OVERRIDE_VERSION_RE.match(candidate):
        return candidate
    return None


def _usable_url(value: str | None) -> bool:
    return bool(value and value not in ("NONE", "NOASSERTION"))
