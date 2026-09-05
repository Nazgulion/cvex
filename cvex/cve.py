from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from sqlalchemy.orm import Session

from cvex.config import CvexConfig
from cvex.db.models import ConnectorState, SourceRun
from cvex.ingest import MaterializedRecord, batches, fail_source_run, finish_source_run, materialize_batch
from cvex.util import duration_seconds, parse_dt


def ingest_cve_incremental(session: Session, config: CvexConfig, limit: int | None = None) -> tuple[str, int, str | None, str]:
    years = configured_history_years(config)
    repo_path = sync_cve_repo(config, years=years)
    latest_sha = git_output(repo_path, "rev-parse", "HEAD")
    state = session.get(ConnectorState, "cve")
    previous = state.checkpoint_value if state and state.checkpoint_type == "git_commit_sha" else None
    files = changed_cve_files(repo_path, previous, latest_sha) if previous else cve_files_for_years(repo_path, years)
    run_id, count = ingest_cve_files(session, config, repo_path, files, "sync", "incremental_git" if previous else "initial_history_git", latest_sha, previous, limit, True)
    return run_id, count, previous, latest_sha


def backfill_cve_year(session: Session, config: CvexConfig, year: int, limit: int | None = None, *, repo_path: Path | None = None, commit_sha: str | None = None) -> tuple[str, int, str]:
    repo_path = repo_path or sync_cve_repo(config, years=[year])
    latest_sha = commit_sha or git_output(repo_path, "rev-parse", "HEAD")
    run_id, count = ingest_cve_files(session, config, repo_path, cve_files_for_years(repo_path, [year]), "backfill", "year_git", latest_sha, None, limit, False)
    finish_source_run(session, run_id, "cve", config, {"year": year, "partial": limit is not None})
    return run_id, count, latest_sha


def sync_cve_repo(config: CvexConfig, years: list[int] | None = None) -> Path:
    source = config.sources["cve"]
    if not source.git_url:
        raise ValueError("sources.cve.git_url is required")
    repo_path = cve_repo_path(config)
    repo_path.parent.mkdir(parents=True, exist_ok=True)
    timeout = int(duration_seconds(source.request_timeout))
    if not (repo_path / ".git").exists():
        run_git(None, "clone", "--filter=blob:none", "--no-checkout", "--branch", source.git_ref, source.git_url, str(repo_path), timeout=timeout)
    else:
        run_git(repo_path, "fetch", "origin", source.git_ref, timeout=timeout)
    sparse_paths = [f"cves/{year}" for year in (years or configured_history_years(config))]
    run_git(repo_path, "sparse-checkout", "init", "--cone", timeout=timeout)
    run_git(repo_path, "sparse-checkout", "set", *sparse_paths, timeout=timeout)
    run_git(repo_path, "checkout", "--detach", f"origin/{source.git_ref}", timeout=timeout)
    return repo_path


def cve_repo_path(config: CvexConfig) -> Path:
    return Path(config.sources["cve"].cache_dir) / "cvelistV5"


def configured_history_years(config: CvexConfig) -> list[int]:
    current_year = datetime.now(timezone.utc).year
    start = int(config.history.start_date[:4]) if config.history.start_date else current_year - config.history.lookback_years + 1
    return list(range(start, current_year + 1))


def cve_files_for_years(repo_path: Path, years: Iterable[int]) -> list[Path]:
    files: list[Path] = []
    for year in years:
        directory = repo_path / "cves" / str(year)
        if directory.exists():
            files.extend(path for path in directory.rglob("*.json") if path.is_file() and _is_cve_record_path(path))
    return sorted(files)


def changed_cve_files(repo_path: Path, old_sha: str, new_sha: str) -> list[Path]:
    if old_sha == new_sha:
        return []
    output = git_output(repo_path, "diff", "--name-only", "--diff-filter=AMR", old_sha, new_sha, "--", "cves")
    return sorted(repo_path / line for line in output.splitlines() if _is_cve_record_path(Path(line)) and (repo_path / line).exists())


def parse_cve_record(payload: dict[str, Any]) -> MaterializedRecord | None:
    cve_id = _cve_id(payload)
    if not cve_id:
        return None
    return MaterializedRecord(
        "cve", cve_id, _cve_modified(payload), _cve_published(payload), _cve_withdrawn(payload),
        _normalized_status(payload), _english_description(payload), payload,
    )


def ingest_cve_files(session: Session, config: CvexConfig, repo_path: Path, files: Iterable[Path], run_type: str, mode: str, commit_sha: str, previous_commit_sha: str | None, limit: int | None = None, update_checkpoint: bool = False) -> tuple[str, int]:
    run = SourceRun(source="cve", run_type=run_type, status="running", details={"mode": mode, "commit_sha": commit_sha, "previous_commit_sha": previous_commit_sha})
    session.add(run)
    session.commit()
    run_id = str(run.id)
    seen = changed = 0
    try:
        parsed = _iter_parsed_files(files, limit)
        for batch in batches(parsed, config.processing.source_chunk_size):
            result = materialize_batch(session, batch, run_id)
            seen += result.seen
            changed += result.changed
        checkpoint_type = "git_commit_sha" if update_checkpoint and limit is None else None
        checkpoint_value = commit_sha if update_checkpoint and limit is None else None
        finish_source_run(session, run_id, "cve", config, {"repo_path": str(repo_path), "records_seen": seen, "records_changed": changed, "limited": limit is not None}, checkpoint_type, checkpoint_value)
        return run_id, seen
    except Exception as exc:
        fail_source_run(session, run_id, exc)
        raise


def _iter_parsed_files(files: Iterable[Path], limit: int | None) -> Iterator[MaterializedRecord]:
    count = 0
    for path in files:
        if limit is not None and count >= limit:
            return
        with path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
        record = parse_cve_record(payload)
        if record is not None:
            count += 1
            yield record


def run_git(repo_path: Path | None, *args: str, timeout: int) -> None:
    command = ["git"] + (["-C", str(repo_path)] if repo_path is not None else []) + list(args)
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {(result.stderr or result.stdout or '').strip()}")


def git_output(repo_path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo_path), *args], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {(result.stderr or result.stdout or '').strip()}")
    return result.stdout.strip()


def _is_cve_record_path(path: Path) -> bool:
    return path.suffix == ".json" and path.name.startswith("CVE-")


def _cve_metadata(payload: Any) -> dict[str, Any]:
    return payload.get("cveMetadata") or {} if isinstance(payload, dict) else {}


def _cve_id(payload: dict[str, Any]) -> str | None:
    return _cve_metadata(payload).get("cveId")


def _cve_published(payload: dict[str, Any]):
    return parse_dt(_cve_metadata(payload).get("datePublished"))


def _cve_modified(payload: dict[str, Any]):
    metadata = _cve_metadata(payload)
    return parse_dt(metadata.get("dateUpdated") or metadata.get("datePublished") or metadata.get("dateReserved"))


def _cve_withdrawn(payload: dict[str, Any]):
    metadata = _cve_metadata(payload)
    return parse_dt(metadata.get("dateRejected") or metadata.get("dateUpdated")) if (metadata.get("state") or "").upper() == "REJECTED" else None


def _normalized_status(payload: dict[str, Any]) -> str:
    return "inactive" if (_cve_metadata(payload).get("state") or "").upper() == "REJECTED" else "active"


def _english_description(payload: dict[str, Any]) -> str | None:
    containers = payload.get("containers") or {}
    cna = containers.get("cna") or {} if isinstance(containers, dict) else {}
    descriptions = cna.get("descriptions") or cna.get("rejectedReasons") or [] if isinstance(cna, dict) else []
    return next((entry.get("value") for entry in descriptions if isinstance(entry, dict) and entry.get("lang") == "en"), None)
