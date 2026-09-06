"""Regression coverage for the end-to-end reliability review."""
import os
from contextvars import Context
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest


def test_nvd_catches_up_without_gaps_and_checkpoints_each_window(monkeypatch):
    import cvex.nvd as nvd
    from cvex.config import load_config

    now = datetime(2026, 9, 6, tzinfo=timezone.utc)
    old = now - timedelta(days=300)
    state = SimpleNamespace(checkpoint_value=old.isoformat())
    session = SimpleNamespace(get=lambda *args: state)
    windows, checkpoints = [], []
    monkeypatch.setattr(nvd, "utcnow", lambda: now)

    def ingest(_session, _config, start, end, **kwargs):
        windows.append((datetime.fromisoformat(start.replace("Z", "+00:00")), datetime.fromisoformat(end.replace("Z", "+00:00"))))
        return "run", 1

    def finish(*args):
        checkpoints.append(args[-1])
        if args[-1]:
            state.checkpoint_value = args[-1]

    monkeypatch.setattr(nvd, "ingest_nvd_sync_window", ingest)
    monkeypatch.setattr(nvd, "finish_source_run", finish)
    result = nvd.ingest_nvd_incremental.__wrapped__(session, load_config())
    assert result[1] == 3 and len(checkpoints) == 3
    assert windows[0][0] <= old and windows[-1][1] == now
    assert all(end-start <= timedelta(days=120) for start, end in windows)
    assert all(left[1] == right[0] for left, right in zip(windows, windows[1:]))

    # A later window failure preserves the preceding completed window.
    state.checkpoint_value = old.isoformat()
    windows.clear()
    def interrupted(*args, **kwargs):
        if windows:
            raise OSError("upstream unavailable")
        return ingest(*args, **kwargs)
    monkeypatch.setattr(nvd, "ingest_nvd_sync_window", interrupted)
    with pytest.raises(OSError):
        nvd.ingest_nvd_incremental.__wrapped__(session, load_config())
    assert state.checkpoint_value == windows[0][1].isoformat().replace("+00:00", "Z")
    resumed_from = state.checkpoint_value
    monkeypatch.setattr(nvd, "ingest_nvd_sync_window", ingest)
    windows.clear()
    nvd.ingest_nvd_incremental.__wrapped__(session, load_config(), limit=1)
    assert state.checkpoint_value == resumed_from  # Limited runs cannot advance it.


def test_sse_releases_auth_database_before_streaming(monkeypatch):
    from fastapi.testclient import TestClient
    from starlette.responses import StreamingResponse
    import cvex.web as web

    opened = []
    class DB:
        def __enter__(self):
            opened.append(self)
            return self
        def __exit__(self, *args):
            opened.remove(self)
    class Result:
        def mappings(self): return self
        def first(self): return {"id": "test", "username": "test", "role": "admin", "csrf": "test"}
        def scalar(self): return True
    def short_response(content, **kwargs):
        async def once():
            async for chunk in content:
                assert opened == [], "authentication retained its session during streaming"
                yield chunk
                break
            await content.aclose()
        return StreamingResponse(once(), **kwargs)
    monkeypatch.setattr(web, "factory", lambda: DB)
    monkeypatch.setattr(web, "query", lambda *args, **kwargs: Result())
    monkeypatch.setattr(web, "status_payload", lambda db: {})
    monkeypatch.setattr(web, "StreamingResponse", short_response)
    with TestClient(web.app) as client:
        assert client.get("/api/v1/admin/events").status_code == 200
    assert opened == []


def test_heartbeat_failures_are_logged_without_exception_secrets(caplog):
    import threading
    from cvex.jobs import heartbeat
    called = threading.Event()
    def unavailable():
        called.set()
        raise RuntimeError("sensitive connection detail")
    with heartbeat(unavailable, "test-worker", "running"):
        assert called.wait(1)
    assert "Heartbeat failed for test-worker (RuntimeError)" in caplog.text
    assert "sensitive connection detail" not in caplog.text


postgres = pytest.mark.skipif(not os.getenv("CVEX_TEST_DATABASE_URL"), reason="requires disposable PostgreSQL")


@postgres
def test_login_success_resets_budget_and_clients_are_isolated(monkeypatch):
    from fastapi.testclient import TestClient
    from cvex.config import load_config
    from cvex.db.session import make_session_factory
    from cvex.workspace import password_hash, query
    import cvex.web as web
    monkeypatch.setenv("CVEX_DATABASE_URL", os.environ["CVEX_TEST_DATABASE_URL"])
    factory = make_session_factory(load_config())
    monkeypatch.setattr(web.app.state, "factory", factory, raising=False)
    username = "login-" + uuid4().hex
    with factory() as db:
        query(db, "INSERT INTO cvex.web_user(username,password_hash,role) VALUES(:u,:p,'user')",
              u=username, p=password_hash("review login password"))
        db.commit()
    body = {"username": username, "password": "review login password"}
    address = "client-" + uuid4().hex
    with TestClient(web.app, client=(address, 123)) as client:
        for _ in range(22):
            assert client.post("/api/v1/auth/login", json=body).status_code == 200
        for _ in range(20):
            assert client.post("/api/v1/auth/login", json={**body, "password": "wrong"}).status_code == 401
        assert client.post("/api/v1/auth/login", json=body).status_code == 429
    with TestClient(web.app, client=(address + "-other", 123)) as client:
        assert client.post("/api/v1/auth/login", json=body).status_code == 200


def test_only_trusted_gateway_can_supply_client_ip():
    import asyncio
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
    seen = []
    async def app(scope, receive, send):
        seen.append(scope["client"][0])
    proxy = ProxyHeadersMiddleware(app, trusted_hosts="172.30.254.2")
    async def exercise():
        for peer in ("172.30.254.2", "203.0.113.5"):
            await proxy({"type": "http", "client": (peer, 1), "headers": [(b"x-forwarded-for", b"192.0.2.10")]}, None, None)
    asyncio.run(exercise())
    assert seen == ["192.0.2.10", "203.0.113.5"]


@postgres
def test_source_leases_exclude_other_contexts_and_release_on_error():
    from sqlalchemy import create_engine
    from cvex.source_lock import source_lock
    engine = create_engine(os.environ["CVEX_TEST_DATABASE_URL"])
    def probe(source):
        with source_lock(engine, source):
            return True
    with source_lock(engine, "nvd"):
        assert probe("nvd")  # Nested same operation.
        with pytest.raises(RuntimeError, match="already running"):
            Context().run(probe, "nvd")
        assert Context().run(probe, "cve")  # Independent source stays available.
    with pytest.raises(ValueError):
        with source_lock(engine, "nvd"):
            raise ValueError("interrupted")
    assert Context().run(probe, "nvd")
    engine.dispose()


@postgres
def test_component_database_error_is_isolated_and_scan_is_partial(tmp_path, monkeypatch):
    import json
    from sqlalchemy import select, text
    import cvex.matcher as matcher
    from cvex.config import load_config
    from cvex.db.session import make_session_factory
    from cvex.db.models import Scan, ScanComponentResult
    from cvex.sbom import import_spdx

    monkeypatch.setenv("CVEX_DATABASE_URL", os.environ["CVEX_TEST_DATABASE_URL"])
    payload = {"spdxVersion": "SPDX-2.3", "name": uuid4().hex, "packages": [
        {"SPDXID": "a", "name": "a-broken", "versionInfo": "1"},
        {"SPDXID": "b", "name": "b-healthy", "versionInfo": "1"},
    ]}
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(payload))
    config = load_config()
    factory = make_session_factory(config)
    def match(db, scan_id, component, sources):
        if component.name == "a-broken":
            db.execute(text("SELECT 1/0"))
        return []
    monkeypatch.setattr(matcher, "_match_component", match)
    with factory() as db:
        sbom, _ = import_spdx(db, path)
        sid = matcher.run_match(db, config, sbom)
        assert db.get(Scan, sid).status == "partial"
        results = db.scalars(select(ScanComponentResult).where(ScanComponentResult.scan_id == sid)).all()
        assert sorted(row.status for row in results) == ["error", "not_assessed"]
        from cvex.db.models import SbomDocument, Product
        from cvex.exporter import build_findings_payload, _render_findings_html
        document = db.get(SbomDocument, sbom)
        payload = build_findings_payload(db, config, db.get(Scan, sid), document, db.get(Product, document.product_id), "test")
        assert payload["assessment_errors"][0]["component"] == "a-broken"
        assert "Partial scan" in _render_findings_html(payload)
