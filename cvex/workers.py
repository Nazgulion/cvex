from __future__ import annotations

import signal
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from sqlalchemy.orm import Session, sessionmaker

from cvex.config import CvexConfig
from cvex.cve import ingest_cve_incremental
from cvex.db.models import ConnectorState
from cvex.nvd import ingest_nvd_incremental
from cvex.time import utcnow
from cvex.util import duration_delta, duration_seconds


@dataclass(frozen=True)
class WorkerCycleResult:
    message: str
    sleep_seconds: float


class ShutdownSignal:
    def __init__(self) -> None:
        self.requested = False

    def install(self) -> None:
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)

    def _handle(self, _signum, _frame) -> None:
        self.requested = True


def run_worker_loop(cycle: Callable[[], WorkerCycleResult], *, once: bool = False, max_cycles: int | None = None, shutdown: ShutdownSignal | None = None) -> None:
    stop = shutdown or ShutdownSignal()
    stop.install()
    cycles = 0
    while not stop.requested:
        result = cycle()
        print(result.message, flush=True)
        cycles += 1
        if once or (max_cycles is not None and cycles >= max_cycles):
            return
        remaining = max(result.sleep_seconds, 0.0)
        while remaining > 0 and not stop.requested:
            step = min(remaining, 1.0)
            time.sleep(step)
            remaining -= step


def nvd_sync_cycle(session_factory: sessionmaker[Session], config: CvexConfig, limit: int | None = None) -> WorkerCycleResult:
    return _source_cycle(session_factory, config, "nvd", lambda session: ingest_nvd_incremental(session, config, limit=limit))


def cve_sync_cycle(session_factory: sessionmaker[Session], config: CvexConfig, limit: int | None = None) -> WorkerCycleResult:
    return _source_cycle(session_factory, config, "cve", lambda session: ingest_cve_incremental(session, config, limit=limit))


def _source_cycle(session_factory, config, source: str, action) -> WorkerCycleResult:
    source_config = config.sources[source]
    interval = duration_seconds(source_config.sync_interval)
    session = session_factory()
    try:
        if not source_config.enabled:
            return WorkerCycleResult(f"{source}-sync: disabled", interval)
        retry_wait = _remaining_retry_wait(session, source)
        if retry_wait is not None:
            return WorkerCycleResult(f"{source}-sync: retry_wait sleep={retry_wait:.0f}s", retry_wait)
        _mark_source_attempt(session, source, config)
        result = action(session)
        return WorkerCycleResult(f"{source}-sync: succeeded records={result[1]} run_id={result[0]}", interval)
    except Exception as exc:
        retry = _mark_source_failure(session, source, config, exc)
        return WorkerCycleResult(f"{source}-sync: failed retry_in={retry:.0f}s error={type(exc).__name__}: {exc}", retry)
    finally:
        session.close()


def _mark_source_attempt(session: Session, source: str, config: CvexConfig) -> None:
    now = utcnow()
    state = session.get(ConnectorState, source)
    if state is None:
        state = ConnectorState(source=source, enabled=True)
        session.add(state)
    state.status = "syncing"
    state.last_attempt = now
    state.freshness_sla_seconds = int(duration_seconds(config.sources[source].freshness_sla))
    state.retry_window_seconds = int(duration_seconds(config.sources[source].retry_window))
    state.updated_at = now
    session.commit()


def _mark_source_failure(session: Session, source: str, config: CvexConfig, exc: Exception) -> float:
    session.rollback()
    now = utcnow()
    state = session.get(ConnectorState, source)
    if state is None:
        state = ConnectorState(source=source, enabled=True)
        session.add(state)
    state.error_count = (state.error_count or 0) + 1
    retry = min(duration_seconds(config.sources[source].initial_retry_delay) * 2 ** (state.error_count - 1), duration_seconds(config.sources[source].max_retry_delay))
    retry_window = duration_delta(config.sources[source].retry_window)
    state.status = "retrying"
    state.health = "failed" if state.last_success and now - state.last_success >= retry_window else "degraded"
    state.last_attempt = now
    state.last_error = f"{type(exc).__name__}: {exc}"[:4000]
    state.next_retry_at = now + timedelta(seconds=retry)
    state.updated_at = now
    session.commit()
    return retry


def _remaining_retry_wait(session: Session, source: str) -> float | None:
    state = session.get(ConnectorState, source)
    if state is None or state.status != "retrying" or state.next_retry_at is None:
        return None
    remaining = (state.next_retry_at - utcnow()).total_seconds()
    return remaining if remaining > 0 else None
