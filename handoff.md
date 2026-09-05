# CVEX v2 engineering handoff

The current implementation is documented in [ARCHITECTURE.md](ARCHITECTURE.md). Operator commands are in [cheatsheet.md](cheatsheet.md), and the side-by-side staging procedure is in [transfer-project.md](transfer-project.md).

The v2 baseline is for fresh databases only. Current source payloads are materialized directly in 1,000-CVE PostgreSQL `COPY` batches. NVD and CVE workers are independent. OSV, raw revision history, the normalization queue, and the canonical alias layer are not part of v2.

## Staging acceptance, 2026-09-04

The side-by-side deployment at `/home/daki/cvex-v2` passed the three performance targets on the four-core staging host:

- 2017–2026 NVD+CVE backfill: **27:04.98** (target: under six hours)
- steady-state `sync --source all`: **25.01 seconds** (target: under ten minutes)
- 442-component SBOM match: **24.44 seconds** (target: under one minute)

The second restored 141-component SBOM matched in 6.75 seconds. Both SBOM archives passed SHA-256 verification, were reimported with their original component counts, and produced the existing summary/findings JSON, CSV, and HTML filenames.

The v1-to-v2 golden comparison retained all 214 existing NVD+CVE component/CVE pairs. V2 added 44 findings from current source data and removed none. The comparison artifacts and timing logs are retained under `/home/daki/cvex-v2/reports`.

The final database was approximately 4.5 GB with 381,608 vulnerabilities, 794,669 current severity rows, and 3,189,202 current CPE range rows. Only `cve` and `nvd` occur in `source_payload`; all removed raw, normalization, alias, and source-component tables are absent. A representative indexed `haxx:curl` CPE lookup completed in approximately 310 ms with a cold-cache component.

An unauthenticated NVD checkpoint-bootstrap run processed 368,752 records in 1:17:59 because NVD reported 368,757 records modified in the fallback 120-day window and the public API requires a 10-second inter-page pause. This is a recovery workload, not the incremental benchmark. The next combined incremental sync completed in 25.01 seconds, and the first independent worker cycles subsequently completed successfully.

A deliberately broad 24-hour on-fly validation processed 2,628 current payload rows and completed in 29:11. It produced `onfly.json`, `onfly.csv`, and `onfly.html`, but exposed an optimization opportunity for broad windows: the JSON report was roughly 589 MB because ignored comparisons are retained. Normal on-fly operation should use checkpoint-sized windows.

The v1 code, database, reports, and PostgreSQL container remain intact at `/home/daki/cvex`; its ingestion, OSV, and normalizer services remain stopped. Rollback remains stopping v2 and restarting the v1 services. Keep v1 until the finding comparison is formally signed off.

## Web workspace deployment, 2026-09-05

The authenticated web workspace is deployed at `https://cvex.staging.ast.local:8443` with React/TypeScript, FastAPI, a PostgreSQL report queue, a project scheduler, and the independent source workers. See [WEB_WORKSPACE.md](WEB_WORKSPACE.md) for access, certificates, credentials, operations, and rollback instructions.

- Incremental migration `0002_workspace` applied after a successful custom-format backup at `reports/pre-workspace-2026-09-05.dump` on staging.
- The existing regular CompanyX_Spot_Pro SBOM and its exported report were adopted. The synthetic on-fly document remains outside project retention. Project scheduling is initially disabled.
- Two browser-triggered 442-component report jobs completed in 17.40 and 17.41 seconds, each with 258 findings. Their frozen payloads and artifact sets are stored in the project workspace.
- 57 Python tests passed, including PostgreSQL integration, export interruption/recovery, retention, DST policy, permissions, CSRF, encrypted API keys, and key clearing. The browser workflow passed creation, upload, report generation, HTML viewing/download, schedule editing, and architecture-to-settings navigation.
- The deployed browser smoke check reported no JavaScript errors. The HTTPS endpoint returned 200 with the exported CA explicitly trusted. All five monitored components had fresh telemetry, and both source workers completed successful cycles under database-managed schedules.
- Initial admin credentials are stored only in the private server file `data/workspace/initial-admin.txt`. Change the password after first login; `.web.env` contains the persistent encryption key and must be included in secure backups.

Manage this deployment with both `docker-compose.yml` and `compose.web.yml`, and both `.env` and `.web.env`. Do not start another source-worker deployment against this database.
