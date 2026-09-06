from __future__ import annotations

from datetime import datetime, timezone
from contextlib import ExitStack
from typing import Optional

import typer
from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import func, select

from cvex.config import load_config
from cvex.cve import backfill_cve_year, git_output, ingest_cve_incremental, sync_cve_repo
from cvex.db.models import AffectedCpe, ConnectorState, ReportExport, SbomDocument, Scan, SourcePayload, Vulnerability, VulnerabilitySeverity
from cvex.db.session import make_session_factory
from cvex.exporter import export_findings, export_onfly, export_summary
from cvex.matcher import run_match
from cvex.nvd import backfill_nvd_year, ingest_nvd_incremental, ingest_nvd_sync_window
from cvex.onfly import run_onfly_scan
from cvex.sbom import export_sbom_archive, import_sbom_archive, import_spdx
from cvex.time import utcnow
from cvex.source_lock import source_lock
from cvex.workers import cve_sync_cycle, nvd_sync_cycle, run_worker_loop

app = typer.Typer(no_args_is_help=True)


def _session():
    config = load_config()
    return config, make_session_factory(config)()


@app.command("db-upgrade")
def db_upgrade() -> None:
    command.upgrade(AlembicConfig("alembic.ini"), "head")
    typer.echo("database upgraded")


@app.command()
def sync(source: str = typer.Option("all", "--source", help="cve|nvd|all"), start_date: Optional[str] = None, end_date: Optional[str] = None, cve_id: Optional[str] = None, keyword: Optional[str] = None, cpe: Optional[str] = None, limit: Optional[int] = None) -> None:
    """Fetch and directly materialize current CVE/NVD records."""
    config, session = _session()
    failures = []
    try:
        sources = _selected_sources(config, source)
        filters = bool(start_date or end_date or cve_id or keyword or cpe)
        if "cve" in sources and not filters:
            try:
                run_id, count, old, new = ingest_cve_incremental(session, config, limit)
                typer.echo(f"cve: ingested {count} records commit={old or 'none'}->{new} run_id={run_id}")
            except Exception as exc:
                failures.append("cve")
                typer.echo(f"cve: failed: {type(exc).__name__}: {exc}", err=True)
        elif "cve" in sources:
            typer.echo("cve: skipped because NVD-specific filters were provided")
        if "nvd" in sources:
            try:
                if filters:
                    run_id, count = ingest_nvd_sync_window(session, config, start_date, end_date, cve_id, keyword, cpe, limit)
                    typer.echo(f"nvd: ingested {count} records run_id={run_id}")
                else:
                    run_id, count, start, end = ingest_nvd_incremental(session, config, limit)
                    typer.echo(f"nvd: ingested {count} records window={start}->{end} run_id={run_id}")
            except Exception as exc:
                failures.append("nvd")
                typer.echo(f"nvd: failed: {type(exc).__name__}: {exc}", err=True)
    finally:
        session.close()
    if failures:
        raise typer.Exit(1)


@app.command()
def backfill(source: str = typer.Option("all", "--source", help="cve|nvd|all"), year: Optional[int] = typer.Option(None, "--year"), start_year: Optional[int] = typer.Option(None, "--start-year"), end_year: Optional[int] = typer.Option(None, "--end-year"), limit: Optional[int] = None) -> None:
    """Materialize yearly history, committing every 1,000 CVEs."""
    config, session = _session()
    failures = []
    backfill_started = utcnow()
    latest_cve_sha = None
    leases = ExitStack()
    completed = False
    try:
        sources = _selected_sources(config, source)
        for name in list(sources):
            try:
                leases.enter_context(source_lock(session.get_bind(), name))
            except RuntimeError as exc:
                sources.remove(name)
                failures.append(f"{name}:locked")
                typer.echo(str(exc), err=True)
        current = datetime.now(timezone.utc).year
        years = [year] if year is not None else list(range(start_year or current - config.history.lookback_years + 1, (end_year or current) + 1))
        cve_repo = None
        fixed_cve_sha = None
        if "cve" in sources:
            try:
                cve_repo = sync_cve_repo(config, years)
                fixed_cve_sha = git_output(cve_repo, "rev-parse", "HEAD")
            except Exception as exc:
                failures.append("cve:prepare")
                typer.echo(f"cve: preparation failed: {type(exc).__name__}: {exc}", err=True)
        for selected_year in years:
            if "cve" in sources and cve_repo is not None:
                try:
                    run_id, count, sha = backfill_cve_year(session, config, selected_year, limit, repo_path=cve_repo, commit_sha=fixed_cve_sha)
                    latest_cve_sha = sha
                    typer.echo(f"cve: year={selected_year} records={count} commit={sha} run_id={run_id}")
                except Exception as exc:
                    failures.append(f"cve:{selected_year}")
                    typer.echo(f"cve: year={selected_year} failed: {type(exc).__name__}: {exc}", err=True)
            if "nvd" in sources:
                try:
                    run_id, count = backfill_nvd_year(session, config, selected_year, limit)
                    typer.echo(f"nvd: year={selected_year} records={count} run_id={run_id}")
                except Exception as exc:
                    failures.append(f"nvd:{selected_year}")
                    typer.echo(f"nvd: year={selected_year} failed: {type(exc).__name__}: {exc}", err=True)
        completed = True
    finally:
        try:
            if completed and limit is None and latest_cve_sha and not any(item.startswith("cve:") for item in failures):
                state = session.get(ConnectorState, "cve")
                state.checkpoint_type = "git_commit_sha"
                state.checkpoint_value = latest_cve_sha
                session.commit()
            if completed and limit is None and "nvd" in locals().get("sources", []) and not any(item.startswith("nvd:") for item in failures):
                state = session.get(ConnectorState, "nvd")
                state.checkpoint_type = "last_modified_timestamp"
                state.checkpoint_value = backfill_started.isoformat(timespec="seconds").replace("+00:00", "Z")
                session.commit()
        finally:
            session.close()
            leases.close()
    if failures:
        raise typer.Exit(1)


@app.command()
def worker(kind: str = typer.Argument(..., help="cve-sync|nvd-sync"), limit: Optional[int] = None, once: bool = False, max_cycles: Optional[int] = None) -> None:
    import os
    if os.getenv("CVEX_WORKSPACE_ENABLED") == "true" and not once and not max_cycles and not limit and kind in {"cve-sync", "nvd-sync"}:
        from cvex.runtime import source_loop
        source_loop(kind.split("-")[0])
        return
    config = load_config()
    factory = make_session_factory(config)
    cycles = {"cve-sync": lambda: cve_sync_cycle(factory, config, limit), "nvd-sync": lambda: nvd_sync_cycle(factory, config, limit)}
    if kind not in cycles:
        raise typer.BadParameter(f"unknown worker kind: {kind}")
    run_worker_loop(cycles[kind], once=once, max_cycles=max_cycles)


@app.command("import-sbom")
def import_sbom(file: str, client: Optional[str] = typer.Option(None, "--client"), product: Optional[str] = typer.Option(None, "--product"), release: Optional[str] = typer.Option(None, "--release")) -> None:
    _config, session = _session()
    try:
        sbom_id, count = import_spdx(session, file, client, product, release)
        typer.echo(f"sbom_id={sbom_id}\ncomponents={count}")
    finally:
        session.close()


@app.command("export-sboms")
def export_sboms(out_dir: str = typer.Option(..., "--out-dir")) -> None:
    """Archive raw stored SBOMs and product metadata before v2 cutover."""
    _config, session = _session()
    try:
        manifest, count = export_sbom_archive(session, out_dir)
        typer.echo(f"sboms={count}\nmanifest={manifest}")
    finally:
        session.close()


@app.command("import-sbom-archive")
def import_archive(manifest: str) -> None:
    """Reimport a v1 SBOM archive, preserving synthetic document components."""
    _config, session = _session()
    try:
        for sbom_id, count in import_sbom_archive(session, manifest):
            typer.echo(f"sbom_id={sbom_id} components={count}")
    finally:
        session.close()


@app.command()
def match(sbom_id: str, include_inactive: bool = False, strict_freshness: bool = False, source: str = typer.Option("all", "--source", help="cve|nvd|all")) -> None:
    config, session = _session()
    try:
        scan_id = run_match(session, config, sbom_id, strict_freshness, _selected_sources(config, source))
        typer.echo(f"scan_id={scan_id}")
    finally:
        session.close()


@app.command()
def onfly(watchlist: str = typer.Option(..., "--watchlist"), since: Optional[str] = None, until: Optional[str] = None, source: str = typer.Option("all", "--source", help="cve|nvd|all")) -> None:
    config, session = _session()
    try:
        typer.echo(f"scan_id={run_onfly_scan(session, config, watchlist, since, until, source)}")
    finally:
        session.close()


@app.command()
def export(scan_id: str, out_dir: Optional[str] = None, export_type: str = typer.Option("all", "--type", help="summary|findings|onfly|all")) -> None:
    config, session = _session()
    try:
        if export_type == "onfly":
            paths = export_onfly(session, config, scan_id, out_dir)
        else:
            paths = {}
            if export_type in ("summary", "all"):
                paths["summary"] = export_summary(session, config, scan_id, out_dir)
            if export_type in ("findings", "all"):
                paths.update({f"findings_{name}": path for name, path in export_findings(session, config, scan_id, out_dir).items()})
        for name, path in paths.items():
            typer.echo(f"{name}={path}")
    finally:
        session.close()


@app.command()
def status() -> None:
    _config, session = _session()
    try:
        for state in session.execute(select(ConnectorState).order_by(ConnectorState.source)).scalars():
            typer.echo(f"{state.source}: enabled={state.enabled} status={state.status} health={state.health} last_success={state.last_success} checkpoint={state.checkpoint_value}")
        counts = {
            "source_payloads": session.scalar(select(func.count()).select_from(SourcePayload)),
            "vulnerabilities": session.scalar(select(func.count()).select_from(Vulnerability)),
            "severities": session.scalar(select(func.count()).select_from(VulnerabilitySeverity)),
            "affected_cpes": session.scalar(select(func.count()).select_from(AffectedCpe)),
            "sboms": session.scalar(select(func.count()).select_from(SbomDocument)),
            "scans": session.scalar(select(func.count()).select_from(Scan)),
            "exports": session.scalar(select(func.count()).select_from(ReportExport)),
        }
        typer.echo(" ".join(f"{key}={value}" for key, value in counts.items()))
    finally:
        session.close()


def _selected_sources(config, source: str) -> list[str]:
    if source not in ("all", "cve", "nvd"):
        raise typer.BadParameter(f"unknown source: {source}")
    names = ["cve", "nvd"] if source == "all" else [source]
    return [name for name in names if name in config.sources and config.sources[name].enabled]


@app.command("web")
def web(host: str = "0.0.0.0", port: int = 8000):
    """Serve the authenticated workspace API and frontend."""
    import uvicorn
    uvicorn.run("cvex.web:app", host=host, port=port)


@app.command("workspace-worker")
def workspace_worker(kind: str):
    """Run scheduler or report-worker."""
    if kind not in {"scheduler", "report-worker"}:
        raise typer.BadParameter("Expected scheduler or report-worker")
    from cvex.jobs import serve_background
    serve_background(kind)


@app.command("create-user")
def create_user(username: str, admin: bool = False):
    """Provision an account; password is prompted and never echoed."""
    from cvex.workspace import password_hash, query
    password = typer.prompt("Password (minimum 12 characters)", hide_input=True, confirmation_prompt=True)
    _config, session = _session()
    try:
        query(session, "INSERT INTO cvex.web_user(username,password_hash,role) VALUES(:u,:p,:r)", u=username, p=password_hash(password), r="admin" if admin else "user")
        session.commit()
        typer.echo("Account created")
    finally:
        session.close()


@app.command("list-sboms")
def list_sboms():
    """List stored SBOM IDs, names and product metadata."""
    from cvex.workspace import rows
    _config, session = _session()
    try:
        for row in rows(session, "SELECT s.id,p.client_name,p.product_name,p.release_version,s.name FROM cvex.sbom_document s JOIN cvex.product p ON p.id=s.product_id ORDER BY s.imported_at DESC"):
            typer.echo(" | ".join(str(v or "") for v in row.values()))
    finally:
        session.close()


@app.command("adopt-projects")
def adopt_projects():
    """Adopt existing regular SBOMs and report copies; schedules remain disabled."""
    from cvex.adopt import adopt_existing
    config, session = _session()
    try:
        typer.echo(f"adopted_sboms={adopt_existing(session, config)}")
    finally:
        session.close()
