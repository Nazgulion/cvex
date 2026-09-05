# CVEX v2 safe staging cutover

This is a side-by-side cutover. Never restore the v1 database into the v2 schema and never reuse the v1 PostgreSQL directory.

1. From the retained v1 deployment, export raw SBOMs and metadata:

   ```bash
   cd ~/cvex
   docker compose run --rm cvex export-sboms --out-dir /app/reports/sbom-archive
   docker compose --profile workers stop
   ```

2. Retain `~/cvex`, its database, dump, caches, and reports. Copy v2 source without `data`, `.env`, caches, or reports:

   ```bash
   rsync -az --exclude=.git/ --exclude=.venv/ --exclude=data/ --exclude=reports/ ./ HOST:~/cvex-v2/
   ```

3. On staging, create a distinct `~/cvex-v2/.env`, data directory, cache, and reports. Use an explicit Compose project name so resources cannot collide:

   ```bash
   cd ~/cvex-v2
   mkdir -p data/postgres data/cache data/status reports
   docker compose -p cvex-v2 up -d postgres
   docker compose -p cvex-v2 run --rm --build cvex db-upgrade
   ```

4. Backfill and record wall time:

   ```bash
   time docker compose -p cvex-v2 run --rm cvex backfill --source all --start-year 2017 --end-year 2026
   docker compose -p cvex-v2 run --rm cvex status
   ```

5. Copy the SBOM archive into v2. For each manifest row, run `import-sbom` with its client, product, and release. Run `match` and `export --type all` for each new SBOM UUID.

6. Compare the v2 NVD+CVE findings to retained v1 reports. Record incremental sync time, scan time, database size, and `EXPLAIN (ANALYZE, BUFFERS)` output for the CPE lookup.

Acceptance requires a 2017–2026 backfill under six hours, incremental sync under ten minutes, typical scan under one minute, preserved report contracts, and absence of v1 queue/source tables. Until acceptance, rollback is:

```bash
cd ~/cvex-v2 && docker compose -p cvex-v2 --profile workers down
cd ~/cvex && docker compose --profile workers up -d
```
