from __future__ import annotations

import gzip
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

import requests
from sqlalchemy.orm import Session

from cvex.config import CvexConfig
from cvex.cpe import parse_cpe
from cvex.db.models import ConnectorState, SourceRun
from cvex.ingest import CpeRecord, MaterializedRecord, SeverityRecord, batches, fail_source_run, finish_source_run, materialize_batch
from cvex.time import utcnow
from cvex.util import duration_seconds, parse_dt

NVD_MAX_WINDOW = timedelta(days=120)


def fetch_nvd_records(config: CvexConfig, start_date: str | None = None, end_date: str | None = None, cve_id: str | None = None, keyword: str | None = None, cpe_name: str | None = None, limit: int | None = None, date_mode: str = "published") -> list[dict[str, Any]]:
    return list(iter_nvd_api_records(config, start_date, end_date, cve_id, keyword, cpe_name, limit, date_mode))


def iter_nvd_api_records(config: CvexConfig, start_date: str | None = None, end_date: str | None = None, cve_id: str | None = None, keyword: str | None = None, cpe_name: str | None = None, limit: int | None = None, date_mode: str = "published") -> Iterator[dict[str, Any]]:
    nvd = config.sources["nvd"]
    params: dict[str, Any] = {"resultsPerPage": 2000, "startIndex": 0}
    if cve_id:
        params["cveId"] = cve_id
    if keyword:
        params["keywordSearch"] = keyword
    if cpe_name:
        params["cpeName"] = cpe_name
    if bool(start_date) != bool(end_date):
        raise ValueError("NVD date filters require both start and end")
    if start_date and end_date:
        _validate_nvd_window(start_date, end_date)
        prefix = "pub" if date_mode == "published" else "lastMod"
        params[f"{prefix}StartDate"] = start_date
        params[f"{prefix}EndDate"] = end_date
    headers = {"apiKey": nvd.api_key} if nvd.api_key else {}
    pause = nvd.api_key_request_pause if nvd.api_key else nvd.no_key_request_pause
    emitted = 0
    while True:
        response = requests.get(nvd.api_url, params=params, headers=headers, timeout=duration_seconds(nvd.request_timeout))
        response.raise_for_status()
        payload = response.json()
        page = payload.get("vulnerabilities") or []
        for wrapper in page:
            if limit is not None and emitted >= limit:
                return
            emitted += 1
            yield wrapper
        total = int(payload.get("totalResults", emitted))
        params["startIndex"] += int(payload.get("resultsPerPage", len(page) or 2000))
        if params["startIndex"] >= total or not page:
            return
        time.sleep(duration_seconds(pause or "10s"))


def parse_nvd_record(wrapper: dict[str, Any]) -> MaterializedRecord | None:
    cve = wrapper.get("cve", wrapper)
    cve_id = cve.get("id")
    if not cve_id:
        return None
    description = next((row.get("value") for row in cve.get("descriptions") or [] if row.get("lang") == "en"), None)
    status = "inactive" if "reject" in (cve.get("vulnStatus") or "active").lower() else "active"
    severities = tuple(
        SeverityRecord(row["severity_type"], index, row["score"], row["vector"], row["label"], row["raw"])
        for index, row in enumerate(_extract_severities(cve))
    )
    cpes = []
    for match in _iter_cpe_matches(cve.get("configurations") or []):
        criteria = match.get("criteria") or match.get("cpe23Uri") or match.get("cpe22Uri")
        parsed = parse_cpe(criteria)
        cpes.append(CpeRecord(
            criteria, parsed.part if parsed else None, parsed.vendor if parsed else None,
            parsed.product if parsed else None, parsed.component_version if parsed else None,
            match.get("vulnerable"), match.get("matchCriteriaId"),
            match.get("versionStartIncluding") or match.get("versionStartExcluding"),
            match.get("versionEndIncluding") or match.get("versionEndExcluding"),
            True if match.get("versionStartIncluding") else False if match.get("versionStartExcluding") else None,
            True if match.get("versionEndIncluding") else False if match.get("versionEndExcluding") else None,
            match,
        ))
    return MaterializedRecord(
        "nvd", cve_id, parse_dt(cve.get("lastModified")), parse_dt(cve.get("published")), None,
        status, description, wrapper, severities, tuple(cpes),
    )


def ingest_nvd_records(session: Session, config: CvexConfig, records: Iterable[dict[str, Any]], mode: str = "bounded_api", commit: bool = True, *, run: SourceRun | None = None) -> tuple[str, int]:
    del commit
    if run is None:
        run = SourceRun(source="nvd", run_type="backfill" if mode == "yearly_feed" else "sync", status="running", details={"mode": mode})
        session.add(run)
        session.commit()
    run_id = str(run.id)
    seen = changed = 0
    try:
        parsed = (record for wrapper in records if (record := parse_nvd_record(wrapper)) is not None)
        for batch in batches(parsed, config.processing.source_chunk_size):
            result = materialize_batch(session, batch, run_id)
            seen += result.seen
            changed += result.changed
        finish_source_run(session, run_id, "nvd", config, {"records_seen": seen, "records_changed": changed})
        return run_id, seen
    except Exception as exc:
        fail_source_run(session, run_id, exc)
        raise


def ingest_nvd_sync_window(session: Session, config: CvexConfig, start_date: str | None = None, end_date: str | None = None, cve_id: str | None = None, keyword: str | None = None, cpe_name: str | None = None, limit: int | None = None, date_mode: str = "published") -> tuple[str, int]:
    return ingest_nvd_records(session, config, iter_nvd_api_records(config, start_date, end_date, cve_id, keyword, cpe_name, limit, date_mode), mode=f"{date_mode}_api")


def ingest_nvd_incremental(session: Session, config: CvexConfig, limit: int | None = None) -> tuple[str, int, str, str]:
    now = utcnow()
    state = session.get(ConnectorState, "nvd")
    checkpoint = _parse_checkpoint(state.checkpoint_value if state else None) or now - NVD_MAX_WINDOW
    overlap = timedelta(seconds=duration_seconds(config.sync.incremental_overlap))
    start = max(checkpoint - overlap, now - NVD_MAX_WINDOW)
    start_s, end_s = _nvd_time(start), _nvd_time(now)
    run_id, count = ingest_nvd_sync_window(session, config, start_s, end_s, limit=limit, date_mode="modified")
    finish_source_run(session, run_id, "nvd", config, {"window_start": start_s, "window_end": end_s, "partial": limit is not None}, "last_modified_timestamp" if limit is None else None, end_s if limit is None else None)
    return run_id, count, start_s, end_s


def backfill_nvd_year(session: Session, config: CvexConfig, year: int, limit: int | None = None) -> tuple[str, int]:
    source = config.sources["nvd"]
    url = f"{source.feed_base_url.rstrip('/')}/nvdcve-2.0-{year}.json.gz"
    cache_dir = Path(source.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / f"nvdcve-2.0-{year}.json.gz"
    run = SourceRun(source="nvd", run_type="backfill", status="running", details={"mode": "yearly_feed", "year": year, "feed_url": url})
    session.add(run)
    session.commit()
    run_id = str(run.id)
    try:
        with requests.get(url, timeout=duration_seconds(source.request_timeout), stream=True) as response:
            response.raise_for_status()
            with target.open("wb") as output:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    output.write(chunk)
    except Exception as exc:
        fail_source_run(session, run_id, exc)
        raise
    run_id, count = ingest_nvd_records(session, config, iter_nvd_feed(target, limit), mode="yearly_feed", run=run)
    finish_source_run(session, run_id, "nvd", config, {"feed_url": url, "cache_path": str(target), "year": year})
    return run_id, count


def iter_nvd_feed(path: Path, limit: int | None = None) -> Iterator[dict[str, Any]]:
    try:
        import ijson
    except ImportError:  # pragma: no cover
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            rows = json.load(fh).get("vulnerabilities") or []
            yield from rows[:limit] if limit is not None else rows
        return
    with gzip.open(path, "rb") as fh:
        for index, row in enumerate(ijson.items(fh, "vulnerabilities.item", use_float=True)):
            if limit is not None and index >= limit:
                return
            yield row


def _extract_severities(cve: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for metric_name, entries in (cve.get("metrics") or {}).items():
        for entry in entries or []:
            cvss = entry.get("cvssData") or {}
            score = cvss.get("baseScore")
            rows.append({"severity_type": metric_name, "score": float(score) if score is not None else None, "vector": cvss.get("vectorString"), "label": entry.get("baseSeverity") or cvss.get("baseSeverity"), "raw": entry})
    return rows


def _iter_cpe_matches(configurations: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for config in configurations:
        for node in config.get("nodes", []) or []:
            yield from _iter_node_matches(node)


def _iter_node_matches(node: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield from node.get("cpeMatch", []) or []
    for child in node.get("children", []) or []:
        yield from _iter_node_matches(child)


def _validate_nvd_window(start: str, end: str) -> None:
    start_dt, end_dt = parse_dt(start), parse_dt(end)
    if start_dt is None or end_dt is None or start_dt > end_dt:
        raise ValueError("invalid NVD date window")
    if end_dt - start_dt > NVD_MAX_WINDOW:
        raise ValueError("NVD date windows may not exceed 120 days")


def _parse_checkpoint(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def _nvd_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
