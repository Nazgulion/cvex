# CVEX web workspace

The web application adds internal accounts, company projects, versioned SPDX JSON uploads, cron-driven scan/export jobs, a live architecture view, and runtime source settings. It uses the existing compact vulnerability database. The source synchronization workers and project report jobs have independent schedules.

## First deployment

Back up PostgreSQL and report files before applying the additive migration. These commands assume the existing staging deployment at `~/cvex-v2`.

```bash
cd ~/cvex-v2
docker compose -p cvex-v2 build cvex
docker compose -p cvex-v2 run --rm cvex db-upgrade

# Creates .web.env and a private initial-admin credential file, without printing secrets.
docker compose -p cvex-v2 run --rm \
  -v /home/daki/cvex-v2:/deployment -w /deployment \
  --entrypoint python cvex /app/tools/bootstrap_web.py

# Copy existing regular SBOM/report history into project workspaces.
docker compose -p cvex-v2 run --rm \
  -v /home/daki/cvex-v2/data/workspace:/var/lib/cvex/workspace \
  -e CVEX_WORKSPACE_ROOT=/var/lib/cvex/workspace cvex adopt-projects

docker compose --env-file .env --env-file .web.env -p cvex-v2 \
  -f docker-compose.yml -f compose.web.yml --profile workers \
  up -d --build web scheduler report-worker cve-worker nvd-worker gateway
```

Open `https://cvex.staging.ast.local:8443`. Caddy uses an internal certificate authority for this internal hostname; import its public root certificate into your browser's trusted authorities before signing in. Do not import a private key.

```bash
docker compose --env-file .env --env-file .web.env -p cvex-v2 \
  -f docker-compose.yml -f compose.web.yml cp \
  gateway:/data/caddy/pki/authorities/local/root.crt ./reports/cvex-local-ca.crt
```

The initial username/password are in `data/workspace/initial-admin.txt` (mode 0600). Use the account settings icon beside your username to change the password; this signs out all existing sessions. Delete the initial credential file after changing the password. Administrators can create additional accounts through Team or `cvex create-user USERNAME --admin`.

Keep `.web.env`, PostgreSQL, `data/workspace`, and Caddy's data in your backups. The encryption key in `.web.env` is required to decrypt saved API keys. Never overwrite it during upgrades.

## Daily use

- Projects → New project → enter company/project → upload SPDX JSON with a version label.
- The first version becomes active. Later uploads require “Make active” before scheduled runs use them.
- “Run now” queues matching and automatic JSON/CSV/HTML export. The selected version is fixed when the job is queued.
- “View HTML” opens a stored report in a separate tab. The download icon saves HTML; CSV and JSON links download those formats.
- Admins use each project's Schedule button to enable five-field cron scheduling. Default timezone is Europe/Belgrade; schedules start paused.
- Admins use Architecture to inspect live workers, queues, source status, and storage. Click a source node to open its schedule and credential settings.
- Architecture → Source sync history shows the latest 12 ingestion runs, start/finish times, ingestion duration, processed records and combined added/updated records. CVE Git preparation is not included in this duration; missing counts are shown as a dash.
- A project's “Selected for new scans” panel identifies its active SBOM filename and version. The version label describes your software release; it is not an API key.
- NVD starts with a two-hour interval and CVE List with 30 minutes. Changes apply between cycles; a running cycle completes using its current settings.

Scheduled time is enqueue time. The initial deployment runs one report at a time. Repeated manual requests reuse the existing queued/active job. Overlapping scheduled occurrences are logged as skipped. Restart recovery enqueues at most one catch-up job per schedule. DST gaps are skipped and repeated local times execute once.

Reports run with local data even if sources are stale. Their captured source freshness is shown with the result. Each report's database snapshot and exported content are frozen; future synchronization does not alter it.

The newest 30 published runs per project are retained across all versions, including reports marked `partial` when some components could not be assessed. Cleanup removes old managed report directories and detailed scan results, preserving uploads and source intelligence. Failed jobs do not displace published reports: after retries are exhausted their scan/snapshot data and temporary artifacts are removed, while the failure metadata stays visible. File deletion uses a durable database outbox so filesystem failures can be retried without rolling back publication state. Explicitly adopted report copies join this policy; original pre-adoption report files remain as archival copies. Synthetic on-fly SBOMs/reports are not adopted.

## Upgrading to the review-hardening release

Back up the database and workspace first. Stop the running web, scheduler, report and source workers before applying migration `0003_review_hardening`, then rebuild and restart them together. This migration preserves existing frozen payloads in `report_snapshot` and removes their duplicate column from `report_job`; it is **not compatible with the previous web worker image**. To restore that image, stop services and downgrade to `0002_workspace` first (or restore the pre-upgrade backup).

The gateway now has a dedicated proxy network. The web service trusts only `CVEX_TRUSTED_PROXY_IP` (default `172.30.254.2`) for forwarded client addresses. The web service has its own fixed `CVEX_WEB_PROXY_IP` (default `172.30.254.3`) so automatic address allocation cannot claim the gateway address during startup. `CVEX_PROXY_SUBNET` defaults to `172.30.254.0/28`; change all three together if that subnet conflicts with your environment. Do not publish the web service's port 8000 directly. Successful logins reset that client's attempt counter.

CLI synchronization/backfills and scheduled workers share per-source locks. If a source is already running, a CLI invocation reports that it is busy; retry after it finishes. Different sources remain independently executable. NVD recovers old checkpoints through consecutive windows of at most 120 days, saving each completed window; limited runs do not advance checkpoints. Older timestamped payloads cannot replace newer stored data.

## Configuration and recovery

`compose.web.yml` extends the existing Compose deployment. Always include both files and both environment files when managing web services. Do not run another source-worker deployment against the same database.

Runtime schedules and source settings live in PostgreSQL. NVD credentials are encrypted and masked in HTTP responses. Blank credential fields preserve the saved key; “Clear API key” removes it. Static configuration still supplies immutable connector endpoints and other defaults.

Report workers use PostgreSQL advisory locks and durable job states. Interrupted exports resume from frozen data; interrupted scans roll back and restart. After three failed attempts the job is marked failed and another manual run can be requested. Cleanup is retried by the scheduler.

The browser updates telemetry every three seconds. Source batch counts measure committed CVEs, while report progress counts SBOM components. A missing heartbeat is displayed as stale rather than as active processing. No percentage is displayed for source downloads whose total is not known.

For rollback to the original CLI-only v2 runtime, stop the web scheduler, executor, gateway, and web-enabled source workers and restart the prior CLI image with the base Compose configuration. The workspace tables can remain. Rollback to an older **web** image requires the schema procedure above. Preserve the database backup until acceptance.

## Development and verification

The UI-performance release adds migration `0004_workspace_indexes`; run `db-upgrade` before starting the rebuilt application. It adds indexes for project history, retention and recent source runs. It does not modify existing report content.

The architecture module is lazy-loaded. Polling waits for each request to finish and pauses in hidden tabs; live metrics are connected only while Architecture is visible. Hashed build assets are cached immutably, HTML is revalidated, authenticated API responses are not cached, and responses are compressed (SSE is excluded). CSV downloads prefix formula-like text with an apostrophe for spreadsheet safety; JSON retains the original values.

```bash
uv sync --extra dev
npm ci --prefix frontend
npm run build --prefix frontend
docker compose -p cvex-web-test -f compose.test.yml up -d --wait
export CVEX_DATABASE_URL=postgresql+psycopg://cvex:workspace-test-only@127.0.0.1:55439/cvex
export CVEX_TEST_DATABASE_URL="$CVEX_DATABASE_URL"
uv run cvex db-upgrade
uv run pytest
```

Browser tests use the disposable database, `tests/browser_setup.py`, a local web process with `CVEX_COOKIE_SECURE=false`, and a local `workspace-worker report-worker` process. Start them with a shared `CVEX_WORKSPACE_ROOT`, then run `frontend/node_modules/.bin/playwright test -c frontend/playwright.config.ts`. The test uses installed Google Chrome and covers creation, upload, real report execution, HTML viewing, downloads, schedules, and diagram-to-settings navigation.

For frontend development use `npm run dev --prefix frontend`; Vite proxies `/api` to the local backend on port 8000. Production uses secure cookies and the HTTPS gateway.
