import json
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest

from cvex.spdx_validation import validate_spdx


def test_proxy_peers_have_distinct_fixed_addresses():
    from ipaddress import ip_address, ip_network
    from pathlib import Path
    import yaml

    config = yaml.safe_load((Path(__file__).parents[1] / "compose.web.yml").read_text())
    services = config["services"]
    addresses = [services[name]["networks"]["proxy"]["ipv4_address"] for name in ("web", "gateway")]
    # Check the shipped defaults as well as requiring explicit peer addresses.
    addresses = [ip_address(value.split(":-", 1)[1].removesuffix("}")) for value in addresses]
    subnet = config["networks"]["proxy"]["ipam"]["config"][0]["subnet"]
    network = ip_network(subnet.split(":-", 1)[1].removesuffix("}"))
    assert len(set(addresses)) == 2
    assert all(address in network for address in addresses)
    assert services["web"]["environment"]["FORWARDED_ALLOW_IPS"] == services["gateway"]["networks"]["proxy"]["ipv4_address"]


@pytest.mark.parametrize("fields", [
    {"packages": [{"SPDXID": "p", "name": 3}]},
    {"packages": [{"SPDXID": "p", "name": "curl", "versionInfo": {}}]},
    {"packages": [{"SPDXID": "p", "name": "curl", "externalRefs": ["bad"]}]},
    {"packages": [{"SPDXID": "p", "name": "curl"}]*2},
    {"creationInfo": {"creators": "bad"}},
    {"relationships": [None]},
])
def test_malformed_spdx_is_rejected_before_import(fields):
    with pytest.raises(ValueError):
        validate_spdx({"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "p", "name": "curl"}], **fields})


def test_csv_cells_neutralize_formulas_but_preserve_numbers():
    from cvex.exporter import _csv_cell, _SafeCsvWriter
    from io import StringIO
    for value in ["=1+1", "+1", "-1", "@SUM(A1)", "\t =1", "\r=1"]:
        assert _csv_cell(value) == "'" + value
    assert _csv_cell(-1) == -1
    assert _csv_cell("curl") == "curl"
    output = StringIO()
    writer = _SafeCsvWriter(output, fieldnames=["name"])
    writer.writeheader()
    writer.writerow({"name": "=1+1"})
    assert "'=1+1" in output.getvalue()


def test_empty_nvd_page_is_not_success(monkeypatch):
    import cvex.nvd as nvd
    from cvex.config import load_config
    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"totalResults": 20, "resultsPerPage": 2000, "vulnerabilities": []}))
    with pytest.raises(RuntimeError, match="empty page"):
        list(nvd.iter_nvd_api_records(load_config()))


@pytest.mark.skipif(not os.getenv("CVEX_TEST_DATABASE_URL"), reason="requires disposable PostgreSQL")
def test_failed_upload_rolls_back_import_and_retained_reports_stay_visible(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from cvex.config import load_config
    from cvex.db.session import make_session_factory
    from cvex.workspace import query
    import cvex.web as web
    monkeypatch.setenv("CVEX_DATABASE_URL", os.environ["CVEX_TEST_DATABASE_URL"])
    monkeypatch.setenv("CVEX_WORKSPACE_ROOT", str(tmp_path))
    factory = make_session_factory(load_config())
    monkeypatch.setattr(web.app.state, "factory", factory, raising=False)
    # Only this test bypasses auth; authentication is exercised separately.
    web.app.dependency_overrides[web.identity] = lambda: {"username": "test", "role": "admin"}
    try:
        with TestClient(web.app, raise_server_exceptions=False) as client:
            pid = client.post('/api/v1/projects', json={"company": "Test", "name": uuid4().hex}).json()["id"]
            payload = {"spdxVersion": "SPDX-2.3", "name": uuid4().hex, "packages": [{"SPDXID": "p", "name": "curl", "versionInfo": "1.0.0"}]}
            original_query = web.query
            def fail_publication(db, sql, **params):
                if "INSERT INTO cvex.project_version" in sql:
                    raise RuntimeError("simulated publication failure")
                return original_query(db, sql, **params)
            monkeypatch.setattr(web, "query", fail_publication)
            response = client.post(f'/api/v1/projects/{pid}/versions', files={"file": ("sbom.json", json.dumps(payload), "application/json")})
            assert response.status_code == 500
            with factory() as db:
                assert query(db, "SELECT count(*) FROM cvex.sbom_document WHERE name=:n", n=payload["name"]).scalar() == 0
            assert not list(tmp_path.glob("projects/*/uploads/*.json"))
            monkeypatch.setattr(web, "query", original_query)
            response = client.post(f'/api/v1/projects/{pid}/versions', files={"file": ("sbom.json", json.dumps(payload), "application/json")})
            assert response.status_code == 201
            version = response.json()["id"]
            with factory() as db:
                kept = query(db, "INSERT INTO cvex.report_job(project_id,version_id,trigger,state,created_at,finished_at) VALUES(:p,:v,'manual','succeeded',now()-interval '1 day',now()) RETURNING id", p=pid, v=version).scalar()
                query(db, "INSERT INTO cvex.report_job(project_id,version_id,trigger,state,finished_at) SELECT :p,:v,'manual','failed',now() FROM generate_series(1,110)", p=pid, v=version)
                db.commit()
            result = client.get(f'/api/v1/projects/{pid}')
            assert result.headers['cache-control'] == 'private, no-store'
            assert str(kept) in [row['id'] for row in result.json()['jobs']]
            assert len(result.json()['jobs']) == 71
    finally:
        web.app.dependency_overrides.pop(web.identity, None)
