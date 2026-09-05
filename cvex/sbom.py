from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cvex.db.models import (
    ComponentIdentity,
    ComponentRelationship,
    Product,
    SbomComponent,
    SbomDocument,
    SourceRun,
)
from cvex.time import utcnow
from cvex.util import parse_dt, sha256_bytes
from cvex.versioning import normalize_version


def import_spdx(
    session: Session,
    path: str | Path,
    client: str | None = None,
    product_name: str | None = None,
    release: str | None = None,
) -> tuple[str, int]:
    sbom_path = Path(path)
    data = json.loads(sbom_path.read_text(encoding="utf-8"))
    content_hash = sha256_bytes(sbom_path.read_bytes())
    existing = session.execute(select(SbomDocument).where(SbomDocument.content_sha256 == content_hash)).scalar_one_or_none()
    if existing:
        component_count = session.execute(
            select(SbomComponent).where(SbomComponent.sbom_document_id == existing.id)
        ).scalars().all()
        return str(existing.id), len(component_count)

    inferred_product, inferred_release = _infer_product(data)
    product = _get_or_create_product(
        session,
        client_name=client or _infer_client(data),
        product_name=product_name or inferred_product,
        release_version=release or inferred_release,
    )
    run = SourceRun(source="sbom", run_type="import", status="running", details={"path": str(sbom_path)})
    session.add(run)
    session.flush()
    doc = SbomDocument(
        product_id=product.id,
        format="spdx",
        format_version=data.get("spdxVersion"),
        content_sha256=content_hash,
        name=data.get("name"),
        document_namespace=data.get("documentNamespace"),
        created_by=", ".join((data.get("creationInfo") or {}).get("creators", [])) or None,
        created_at_source=parse_dt((data.get("creationInfo") or {}).get("created")),
        raw_payload=data,
        run_id=run.id,
    )
    session.add(doc)
    session.flush()

    packages_by_id = {pkg["SPDXID"]: pkg for pkg in data.get("packages", []) if pkg.get("SPDXID")}
    variant_map = {
        rel.get("spdxElementId"): rel.get("relatedSpdxElement")
        for rel in data.get("relationships", [])
        if rel.get("relationshipType") == "VARIANT_OF"
    }
    variant_targets = {target for target in variant_map.values() if target}
    component_by_spdx: dict[str, SbomComponent] = {}

    for spdx_id, pkg in packages_by_id.items():
        if spdx_id in variant_targets:
            continue
        upstream_pkg = packages_by_id.get(variant_map.get(spdx_id) or "")
        component = _create_component(session, doc.id, pkg, upstream_pkg)
        component_by_spdx[spdx_id] = component

    session.flush()
    for source_id, upstream_id in variant_map.items():
        from_component = component_by_spdx.get(source_id)
        # Upstream package is folded into the source component in v1.
        if from_component and upstream_id:
            from_component.identities.append(ComponentIdentity(identity_type="spdx_upstream_id", identity_value=upstream_id))

    run.status = "succeeded"
    run.finished_at = utcnow()
    session.commit()
    return str(doc.id), len(component_by_spdx)


def export_sbom_archive(session: Session, out_dir: str | Path) -> tuple[str, int]:
    """Export stored SBOM payloads plus product metadata for a safe v1→v2 cutover."""
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    rows = session.execute(
        select(SbomDocument, Product)
        .join(Product, SbomDocument.product_id == Product.id)
        .order_by(SbomDocument.imported_at, SbomDocument.id)
    ).all()
    manifest = {"schema_version": "1.0", "exported_at": utcnow().isoformat(), "sboms": []}
    for document, product in rows:
        filename = f"{document.id}.json"
        (root / filename).write_text(json.dumps(document.raw_payload, indent=2, sort_keys=True), encoding="utf-8")
        manifest["sboms"].append({
            "file": filename,
            "sbom_id": str(document.id),
            "content_sha256": document.content_sha256,
            "client": product.client_name,
            "product": product.product_name,
            "release": product.release_version,
            "format": document.format,
            "format_version": document.format_version,
            "components": [
                {
                    "source_component_id": component.source_component_id,
                    "component_kind": component.component_kind,
                    "name": component.name,
                    "raw_version": component.raw_version,
                    "normalized_version": component.normalized_version,
                    "version_status": component.version_status,
                    "version_reason": component.version_reason,
                    "supplier": component.supplier,
                    "download_location": component.download_location,
                    "identities": [{"type": identity.identity_type, "value": identity.identity_value} for identity in component.identities],
                }
                for component in session.execute(select(SbomComponent).where(SbomComponent.sbom_document_id == document.id)).scalars()
            ],
        })
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return str(manifest_path), len(rows)


def import_sbom_archive(session: Session, manifest_file: str | Path) -> list[tuple[str, int]]:
    """Recreate archived SBOM documents, including synthetic watchlist documents."""
    manifest_path = Path(manifest_file)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    imported = []
    for entry in manifest.get("sboms") or []:
        existing = session.execute(select(SbomDocument).where(SbomDocument.content_sha256 == entry["content_sha256"])).scalar_one_or_none()
        if existing:
            count = len(session.execute(select(SbomComponent.id).where(SbomComponent.sbom_document_id == existing.id)).all())
            imported.append((str(existing.id), count))
            continue
        raw_payload = json.loads((manifest_path.parent / entry["file"]).read_text(encoding="utf-8"))
        product = _get_or_create_product(session, entry["client"], entry["product"], entry["release"])
        run = SourceRun(source="sbom", run_type="import", status="running", details={"archive": str(manifest_path), "old_sbom_id": entry.get("sbom_id")})
        session.add(run)
        session.flush()
        document = SbomDocument(
            product_id=product.id, format=entry.get("format") or "spdx", format_version=entry.get("format_version"),
            content_sha256=entry["content_sha256"], name=raw_payload.get("name"),
            document_namespace=raw_payload.get("documentNamespace"), raw_payload=raw_payload, run_id=run.id,
        )
        session.add(document)
        session.flush()
        for row in entry.get("components") or []:
            component = SbomComponent(
                sbom_document_id=document.id, source_component_id=row["source_component_id"],
                component_kind=row.get("component_kind") or "package", name=row["name"], raw_version=row.get("raw_version"),
                normalized_version=row.get("normalized_version"), version_status=row.get("version_status") or "unusable",
                version_reason=row.get("version_reason"), supplier=row.get("supplier"), download_location=row.get("download_location"),
            )
            session.add(component)
            session.flush()
            for identity in row.get("identities") or []:
                component.identities.append(ComponentIdentity(identity_type=identity["type"], identity_value=identity["value"]))
        run.status = "succeeded"
        run.finished_at = utcnow()
        session.commit()
        imported.append((str(document.id), len(entry.get("components") or [])))
    return imported


def _get_or_create_product(session: Session, client_name: str, product_name: str, release_version: str) -> Product:
    existing = session.execute(
        select(Product).where(
            Product.client_name == client_name,
            Product.product_name == product_name,
            Product.release_version == release_version,
        )
    ).scalar_one_or_none()
    if existing:
        return existing
    product = Product(client_name=client_name, product_name=product_name, release_version=release_version)
    session.add(product)
    session.flush()
    return product


def _create_component(session: Session, doc_id: str, pkg: dict[str, Any], upstream_pkg: dict[str, Any] | None) -> SbomComponent:
    version_source = upstream_pkg or pkg
    raw_version = version_source.get("versionInfo")
    normalized = normalize_version(raw_version)
    component = SbomComponent(
        sbom_document_id=doc_id,
        source_component_id=pkg["SPDXID"],
        component_kind=_component_kind(pkg["SPDXID"]),
        name=(upstream_pkg or pkg).get("name") or pkg.get("name") or pkg["SPDXID"],
        raw_version=raw_version,
        normalized_version=normalized.normalized,
        version_status=normalized.status,
        version_reason=normalized.reason,
        supplier=(upstream_pkg or pkg).get("supplier"),
        download_location=(upstream_pkg or pkg).get("downloadLocation"),
    )
    session.add(component)
    session.flush()
    component.identities.append(ComponentIdentity(identity_type="spdx_id", identity_value=pkg["SPDXID"]))
    component.identities.append(ComponentIdentity(identity_type="package_name", identity_value=component.name))
    if upstream_pkg:
        component.identities.append(ComponentIdentity(identity_type="upstream_package_name", identity_value=upstream_pkg.get("name") or component.name))
        if upstream_pkg.get("downloadLocation") not in (None, "", "NONE", "NOASSERTION"):
            component.identities.append(ComponentIdentity(identity_type="upstream_repo_url", identity_value=upstream_pkg["downloadLocation"]))
    for ref in pkg.get("externalRefs") or []:
        if ref.get("referenceCategory") == "SECURITY" and ref.get("referenceLocator"):
            ref_type = "cpe" if "cpe" in (ref.get("referenceType") or "").lower() else ref.get("referenceType")
            component.identities.append(ComponentIdentity(identity_type=ref_type, identity_value=ref["referenceLocator"]))
    return component


def _component_kind(spdx_id: str) -> str:
    if "SOURCE" in spdx_id:
        return "source"
    if "UPSTREAM" in spdx_id:
        return "upstream"
    if "PREBUILT" in spdx_id:
        return "prebuilt"
    if "PRODUCT" in spdx_id:
        return "product"
    if "PLATFORM" in spdx_id:
        return "platform"
    return "package"


def _infer_client(data: dict[str, Any]) -> str:
    creators = (data.get("creationInfo") or {}).get("creators", [])
    for creator in creators:
        if creator.startswith("Organization:"):
            return creator.split(":", 1)[1].strip()
    return "unknown"


def _infer_product(data: dict[str, Any]) -> tuple[str, str]:
    name = data.get("name") or "unknown"
    parts = name.split("/")
    product = parts[1] if len(parts) > 1 else name
    release = parts[-1] if parts else name
    return product, release
