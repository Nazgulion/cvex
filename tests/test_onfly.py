import json

import pytest

from cvex.db.models import SourceAffectedComponent, SourceSeverity, SourceVulnerability
from cvex.onfly import MergedCve, WatchlistComponent, _compare_component_to_cve, load_watchlist


def _component(tmp_path, components):
    path = tmp_path / "watchlist.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "client": "client",
                "product": "product",
                "release": "release",
                "components": components,
            }
        ),
        encoding="utf-8",
    )
    return load_watchlist(path).components[0]


def _merged(cve_id, source_vulns, affected=None, severities=None):
    return MergedCve(
        cve_id=cve_id,
        source_vulns=source_vulns,
        affected=affected or [],
        severities=severities or [],
        source_record_ids=["00000000-0000-0000-0000-000000000001"],
        source_modified={"nvd": "2026-08-25T00:00:00Z"},
    )


def test_watchlist_validation_skips_malformed_components(tmp_path):
    path = tmp_path / "watchlist.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "components": [
                    {"component_id": "missing-version", "name": "curl", "aliases": [{"value": "curl"}]},
                    {"component_id": "name-only", "name": "openssl", "normalized_version": "3.0.0"},
                    {
                        "component_id": "usable",
                        "name": "curl",
                        "normalized_version": "8.0.1",
                        "aliases": [{"value": "curl", "type": "package_name", "source": "ai_baseline"}],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    watchlist = load_watchlist(path)

    assert [component.component_id for component in watchlist.components] == ["usable"]
    assert [row["reason"] for row in watchlist.skipped] == [
        "missing_normalized_version",
        "missing_identity_beyond_display_name",
    ]


def test_watchlist_validation_fails_when_no_usable_components(tmp_path):
    path = tmp_path / "watchlist.json"
    path.write_text(json.dumps({"schema_version": "1.0", "components": [{"component_id": "x", "name": "x"}]}), encoding="utf-8")

    with pytest.raises(ValueError, match="zero usable components"):
        load_watchlist(path)


def test_cve_list_text_alias_match_creates_possible(tmp_path):
    component = _component(
        tmp_path,
        [
            {
                "component_id": "curl-1",
                "name": "curl",
                "normalized_version": "8.0.1",
                "aliases": [{"value": "libcurl", "type": "package_name", "source": "ai_baseline"}],
            }
        ],
    )
    cve = _merged(
        "CVE-2026-0001",
        [SourceVulnerability(source="cve", primary_id="CVE-2026-0001", status="active", description="A flaw in libcurl allows denial of service.")],
    )

    outcome = _compare_component_to_cve(component, cve)

    assert outcome.status == "possible"
    assert outcome.match_type == "cve_text_alias"
    assert "trusted AI alias libcurl" in outcome.reason


def test_cve_list_rejected_cve_creates_ignored(tmp_path):
    component = _component(
        tmp_path,
        [
            {
                "component_id": "curl-1",
                "name": "curl",
                "normalized_version": "8.0.1",
                "aliases": [{"value": "curl"}],
            }
        ],
    )
    cve = _merged(
        "CVE-2026-0002",
        [SourceVulnerability(source="cve", primary_id="CVE-2026-0002", status="inactive", description="curl issue")],
    )

    outcome = _compare_component_to_cve(component, cve)

    assert outcome.status == "ignored"
    assert outcome.match_type == "cve_rejected"


def test_nvd_cpe_and_affected_version_creates_confirmed(tmp_path):
    component = _component(
        tmp_path,
        [
            {
                "component_id": "curl-1",
                "name": "curl",
                "normalized_version": "8.0.1",
                "cpes": ["cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"],
            }
        ],
    )
    affected = SourceAffectedComponent(
        cpe_criteria="cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*",
        cpe_vendor="haxx",
        cpe_product="curl",
        vulnerable=True,
        version_start="8.0.0",
        start_inclusive=True,
        version_end="8.1.0",
        end_inclusive=False,
    )
    severity = SourceSeverity(score=8.8, severity_type="cvssMetricV31")
    cve = _merged(
        "CVE-2026-0003",
        [SourceVulnerability(source="nvd", primary_id="CVE-2026-0003", status="active")],
        affected=[affected],
        severities=[("nvd", severity)],
    )

    outcome = _compare_component_to_cve(component, cve)

    assert outcome.status == "confirmed"
    assert outcome.match_type == "package_version"
    assert outcome.matched_range["severity_source"] == "nvd"


def test_nvd_cpe_match_without_decidable_version_creates_probable(tmp_path):
    component = WatchlistComponent(
        component_id="curl-1",
        name="curl",
        normalized_version="",
        raw_version=None,
        cpes=("cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*",),
    )
    affected = SourceAffectedComponent(
        cpe_criteria="cpe:2.3:a:haxx:curl:7.87.0:*:*:*:*:*:*:*",
        cpe_vendor="haxx",
        cpe_product="curl",
        cpe_version="7.87.0",
        vulnerable=True,
    )
    cve = _merged("CVE-2026-0004", [SourceVulnerability(source="nvd", primary_id="CVE-2026-0004", status="active")], affected=[affected])

    outcome = _compare_component_to_cve(component, cve)

    assert outcome.status == "probable"
    assert outcome.match_type == "cpe_version_unknown"


def test_nvd_cpe_match_with_unaffected_version_creates_ignored(tmp_path):
    component = _component(
        tmp_path,
        [
            {
                "component_id": "curl-1",
                "name": "curl",
                "normalized_version": "8.0.1",
                "cpes": ["cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"],
            }
        ],
    )
    affected = SourceAffectedComponent(
        cpe_criteria="cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*",
        cpe_vendor="haxx",
        cpe_product="curl",
        vulnerable=True,
        version_start="7.0.0",
        start_inclusive=True,
        version_end="8.0.0",
        end_inclusive=False,
    )
    cve = _merged("CVE-2026-0005", [SourceVulnerability(source="nvd", primary_id="CVE-2026-0005", status="active")], affected=[affected])

    outcome = _compare_component_to_cve(component, cve)

    assert outcome.status == "ignored"
    assert outcome.match_type == "cpe_version_not_affected"
