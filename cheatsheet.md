# CVEX v2 operator cheatsheet

```bash
# Initialize a fresh v2 database
docker compose run --rm cvex db-upgrade

# Ten calendar years (currently 2017–2026)
docker compose run --rm cvex backfill --source all --start-year 2017 --end-year 2026

# Incremental one-shot syncs
docker compose run --rm cvex sync --source all
docker compose run --rm cvex sync --source nvd --cve-id CVE-2026-0001

# Independent long-running workers
docker compose --profile workers up -d cve-worker nvd-worker

# Archive SBOMs before cutover
docker compose run --rm cvex export-sboms --out-dir /app/reports/sbom-archive
docker compose run --rm cvex import-sbom-archive /app/reports/sbom-archive/manifest.json

# Reimport, scan, and export
docker compose run --rm cvex import-sbom /app/example.json --client CLIENT --product PRODUCT --release RELEASE
docker compose run --rm cvex match SBOM_UUID --source all
docker compose run --rm cvex export SCAN_UUID --type all

# Current-payload delta scan
docker compose run --rm cvex onfly --watchlist /app/watchlist.json --since 2026-09-02T00:00:00Z --source all
docker compose run --rm cvex export SCAN_UUID --type onfly

# Health and compact-table counts
docker compose run --rm cvex status
```

Reports retain the existing `scan-summary.json`, `findings.json`, `findings.csv`, `findings.html`, `onfly.json`, `onfly.csv`, and `onfly.html` names and structures.

NVD custom API ranges must be 120 days or less. A limited validation run does not advance its source checkpoint.
