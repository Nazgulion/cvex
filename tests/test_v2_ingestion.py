from datetime import timedelta
from decimal import Decimal

import pytest

from cvex.cve import parse_cve_record
from cvex.nvd import NVD_MAX_WINDOW, _validate_nvd_window, parse_nvd_record
from cvex.util import stable_json_dumps


def test_nvd_parser_materializes_cvss_and_cpe_bounds():
    record = parse_nvd_record({"cve": {
        "id": "CVE-2026-1000", "published": "2026-01-01T00:00:00Z", "lastModified": "2026-02-01T00:00:00Z",
        "descriptions": [{"lang": "en", "value": "NVD text"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "vectorString": "CVSS:3.1/X", "baseSeverity": "HIGH"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "8.0.0", "versionEndExcluding": "8.1.0",
        }]}]}],
    }})

    assert record.cve_id == "CVE-2026-1000"
    assert record.severities[0].score == 8.8
    assert record.cpes[0].vendor == "haxx"
    assert record.cpes[0].start_inclusive is True
    assert record.cpes[0].end_inclusive is False


def test_cve_parser_marks_rejected_and_uses_rejection_description():
    record = parse_cve_record({
        "cveMetadata": {"cveId": "CVE-2026-1001", "state": "REJECTED", "dateRejected": "2026-02-01T00:00:00Z"},
        "containers": {"cna": {"rejectedReasons": [{"lang": "en", "value": "Rejected by CNA"}]}},
    })

    assert record.status == "inactive"
    assert record.withdrawn is not None
    assert record.description == "Rejected by CNA"


def test_content_hash_is_stable_and_changes_with_payload():
    first = parse_nvd_record({"cve": {"id": "CVE-2026-1002", "descriptions": []}})
    same = parse_nvd_record({"cve": {"id": "CVE-2026-1002", "descriptions": []}})
    changed = parse_nvd_record({"cve": {"id": "CVE-2026-1002", "descriptions": [{"lang": "en", "value": "changed"}]}})
    assert first.sha256 == same.sha256
    assert first.sha256 != changed.sha256


def test_nvd_rejects_windows_over_strict_120_day_limit():
    _validate_nvd_window("2026-01-01T00:00:00Z", "2026-05-01T00:00:00Z")
    with pytest.raises(ValueError, match="120 days"):
        _validate_nvd_window("2026-01-01T00:00:00Z", "2026-05-01T00:00:01Z")
    assert NVD_MAX_WINDOW == timedelta(days=120)


def test_streaming_decimal_values_are_stably_serialized():
    assert stable_json_dumps({"score": Decimal("8.80"), "count": Decimal("2")}) == '{"count":2,"score":8.8}'
