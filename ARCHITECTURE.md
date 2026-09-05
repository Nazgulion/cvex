# CVEX v2 architecture

CVEX v2 stores only the current NVD and CVE List representation of each CVE. It has no raw-record history, normalization queue, canonical alias layer, OSV connector, or exact-version expansion.

## Runtime

- PostgreSQL 16
- independent `cve-worker` and `nvd-worker` services
- the `cvex` image used as an ephemeral CLI for SBOM import, matching, on-fly scans, exports, and status

The workers have separate processes, retries, source runs, and connector checkpoints. Failure of one source does not stop the other.

## Data flow

Each connector parses upstream input into batches of 1,000 CVEs. A batch is copied into PostgreSQL temporary staging tables with `COPY`, then merged with set-based statements in one transaction. The transaction:

1. upserts `source_payload` only when SHA-256 differs;
2. updates the merged `vulnerability` row for changed payloads;
3. for changed NVD CVEs only, replaces current `vulnerability_severity` and `affected_cpe` children.

Every batch commits independently. A source checkpoint advances only when its complete window or segment succeeds, so an interrupted run safely replays already committed batches.

NVD API windows are rejected when they exceed 120 days. Yearly gzip feeds are downloaded as streams and decoded incrementally. CVE List files are read one at a time from a sparse Git checkout.

## Source precedence

- CVE List controls rejected/inactive status.
- NVD controls CVSS and affected CPE data.
- CVE List descriptions are preferred; NVD is the fallback.
- The CVE ID is the shared identity.
- `finding_evidence.source_payload_id` points to the current source payload.
- On-fly scans select current payloads by `source_modified`; historical revisions are intentionally unavailable.

## Schema

Source state: `source_run`, `connector_state`, `source_payload`.

Vulnerability state: `vulnerability`, `vulnerability_severity`, `affected_cpe`.

Workflow state: `product`, `sbom_document`, `sbom_component`, `component_identity`, `component_relationship`, `scan`, `scan_component_result`, `vulnerability_finding`, `finding_evidence`, `report_export`.

The single `0001_initial` Alembic revision is a fresh-database v2 baseline. It is not an in-place v1 migration.

## CLI

Supported commands are `sync`, `backfill`, `import-sbom`, `export-sboms`, `import-sbom-archive`, `match`, `onfly`, `export`, `status`, `worker`, and `db-upgrade`. Source selectors accept `cve`, `nvd`, or `all`. Worker kinds are `cve-sync` and `nvd-sync`.

`export-sboms --out-dir PATH` writes every stored raw SBOM and a `manifest.json` containing its client, product, release, old UUID, content hash, and component identities. `import-sbom-archive MANIFEST` restores both SPDX and synthetic watchlist documents.

## Safe cutover

1. In v1, archive SBOMs with `export-sboms` and retain all reports.
2. Stop but retain `~/cvex`, its database, dump, code, and reports.
3. Deploy v2 under `~/cvex-v2` with a distinct Compose project, `.env`, PostgreSQL directory, cache, and report directory.
4. Apply the fresh schema and backfill 2017–2026.
5. Reimport each manifest entry with its product metadata, then match and export.
6. Compare v2 NVD+CVE findings and measure load time, incremental time, scan time, database size, and query plans.
7. Accept only when no v1/OSV tables exist and the six-hour backfill, ten-minute incremental, and one-minute typical scan targets pass. Rollback is stopping v2 and restarting the retained v1 deployment.
