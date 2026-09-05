"""Run with CVEX_TEST_DATABASE_URL against an already migrated disposable database."""
import os
from uuid import uuid4

TEST_CVE_ID = f"CVE-2099-{int(uuid4().hex[:12], 16)}"

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from cvex.config import load_config
from cvex.cve import parse_cve_record
from cvex.db.models import AffectedCpe, SourcePayload, SourceRun, Vulnerability, VulnerabilitySeverity
from cvex.ingest import materialize_batch
from cvex.nvd import parse_nvd_record

pytestmark = pytest.mark.skipif(not os.getenv("CVEX_TEST_DATABASE_URL"), reason="requires disposable PostgreSQL")


def _nvd(score: float, product: str, modified: str):
    return parse_nvd_record({"cve": {
        "id": TEST_CVE_ID, "published": "2099-01-01T00:00:00Z", "lastModified": modified,
        "descriptions": [{"lang": "en", "value": "NVD fallback"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": f"cpe:2.3:a:test:{product}:*:*:*:*:*:*:*:*"}]}]}],
    }})


def _load(session, source, record):
    run = SourceRun(source=source, run_type="sync", status="running")
    session.add(run)
    session.commit()
    return materialize_batch(session, [record], str(run.id))


def test_direct_load_idempotency_child_replacement_and_precedence():
    engine = create_engine(os.environ["CVEX_TEST_DATABASE_URL"])
    with Session(engine) as session:
        first = _load(session, "nvd", _nvd(8.8, "old-product", "2099-01-02T00:00:00Z"))
        rerun = _load(session, "nvd", _nvd(8.8, "old-product", "2099-01-02T00:00:00Z"))
        assert first.changed == 1 and rerun.changed == 0

        update = _load(session, "nvd", _nvd(5.0, "new-product", "2099-01-03T00:00:00Z"))
        assert update.changed == 1
        assert session.scalar(select(func.count()).select_from(SourcePayload).where(SourcePayload.cve_id == TEST_CVE_ID)) == 1
        assert session.scalar(select(func.count()).select_from(VulnerabilitySeverity).where(VulnerabilitySeverity.cve_id == TEST_CVE_ID)) == 1
        assert session.scalar(select(func.count()).select_from(AffectedCpe).where(AffectedCpe.cve_id == TEST_CVE_ID)) == 1
        assert session.scalar(select(AffectedCpe.cpe_product).where(AffectedCpe.cve_id == TEST_CVE_ID)) == "new-product"

        cve = parse_cve_record({
            "cveMetadata": {"cveId": TEST_CVE_ID, "state": "REJECTED", "dateRejected": "2099-01-04T00:00:00Z"},
            "containers": {"cna": {"rejectedReasons": [{"lang": "en", "value": "Authoritative rejection"}]}},
        })
        _load(session, "cve", cve)
        _load(session, "nvd", _nvd(9.9, "latest-product", "2099-01-05T00:00:00Z"))
        vulnerability = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == TEST_CVE_ID))
        assert vulnerability.status == "inactive"
        assert vulnerability.description == "Authoritative rejection"
        assert vulnerability.description_source == "cve"
