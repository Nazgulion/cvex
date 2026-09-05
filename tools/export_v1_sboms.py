"""Standalone v1 cutover helper; run inside the v1 application container."""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()
    target = Path(args.out_dir)
    target.mkdir(parents=True, exist_ok=True)
    engine = create_engine(os.environ["CVEX_DATABASE_URL"])
    with engine.connect() as connection:
        rows = connection.execute(text("""
            SELECT d.id, d.content_sha256, d.raw_payload, d.format, d.format_version,
                   p.client_name, p.product_name, p.release_version
            FROM cvex.sbom_document d JOIN cvex.product p ON p.id=d.product_id
            ORDER BY d.imported_at, d.id
        """)).mappings().all()
        components = connection.execute(text("""
            SELECT c.sbom_document_id, c.source_component_id, c.component_kind, c.name, c.raw_version,
                   c.normalized_version, c.version_status, c.version_reason, c.supplier, c.download_location,
                   COALESCE(jsonb_agg(jsonb_build_object('type', i.identity_type, 'value', i.identity_value)
                     ORDER BY i.identity_type, i.identity_value) FILTER (WHERE i.id IS NOT NULL), '[]'::jsonb) identities
            FROM cvex.sbom_component c LEFT JOIN cvex.component_identity i ON i.component_id=c.id
            GROUP BY c.id ORDER BY c.sbom_document_id, c.name
        """)).mappings().all()
    components_by_sbom = {}
    for component in components:
        components_by_sbom.setdefault(str(component["sbom_document_id"]), []).append(
            {key: value for key, value in component.items() if key != "sbom_document_id"}
        )
    manifest = {"schema_version": "1.0", "exported_at": datetime.now(timezone.utc).isoformat(), "sboms": []}
    for row in rows:
        filename = f"{row['id']}.json"
        (target / filename).write_text(json.dumps(row["raw_payload"], indent=2, sort_keys=True), encoding="utf-8")
        manifest["sboms"].append({
            "file": filename, "sbom_id": str(row["id"]), "content_sha256": row["content_sha256"],
            "client": row["client_name"], "product": row["product_name"], "release": row["release_version"],
            "format": row["format"], "format_version": row["format_version"],
            "components": components_by_sbom.get(str(row["id"]), []),
        })
    manifest_path = target / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(f"sboms={len(rows)}")
    print(f"manifest={manifest_path}")


if __name__ == "__main__":
    main()
