from cvex.exporter import _build_match_decision, _compact_warnings, _format_warnings, _render_findings_html


def test_decision_marks_direct_cpe_and_package_match_as_strong():
    decision = _build_match_decision(
        {
            "matched": {
                "confidence": "high",
                "match_types": ["cpe_and_package_version"],
                "version_conflict": False,
                "distro_candidate": False,
                "identity_inferred": False,
                "warnings": [],
            },
            "vulnerability": {"inactive": False},
        }
    )

    assert decision["status"] == "matched_strong_evidence"
    assert decision["evidence_strength"] == "strong"
    assert any("SBOM CPE and normalized package version" in factor for factor in decision["factors"])


def test_decision_explains_version_conflict_caveat():
    decision = _build_match_decision(
        {
            "matched": {
                "confidence": "medium",
                "match_types": ["cpe_version"],
                "version_conflict": True,
                "distro_candidate": False,
                "identity_inferred": False,
                "warnings": [],
            },
            "vulnerability": {"inactive": False},
        }
    )

    assert decision["status"] == "matched_with_caveats"
    assert decision["evidence_strength"] == "moderate"
    assert "CPE version and normalized package version differ" in " ".join(decision["factors"])


def test_decision_explains_unconfirmed_distro_candidate():
    decision = _build_match_decision(
        {
            "matched": {
                "confidence": "medium",
                "match_types": ["osv_package_candidate"],
                "version_conflict": False,
                "distro_candidate": True,
                "identity_inferred": False,
                "warnings": [
                    {"code": "distro_context_unconfirmed", "message": "SBOM does not prove distro origin."},
                    {"code": "distro_context_unconfirmed", "message": "Repeated evidence from another distro row."},
                ],
            },
            "vulnerability": {"inactive": False},
        }
    )

    assert decision["status"] == "matched_with_caveats"
    assert decision["evidence_strength"] == "moderate"
    assert "Distro package match is a candidate" in " ".join(decision["factors"])
    assert "Repeated evidence from another distro row" not in " ".join(decision["factors"])
    assert decision["warning_codes"] == ["distro_context_unconfirmed"]
    assert decision["warning_counts"] == {"distro_context_unconfirmed": 2}


def test_compact_warnings_summarizes_repeated_warning_codes():
    warnings = _compact_warnings(
        [
            {"code": "distro_context_unconfirmed", "message": "Matched Alpine:v3.12."},
            {"code": "distro_context_unconfirmed", "message": "Matched Alpine:v3.13."},
            {"code": "version_conflict", "message": "CPE version differs."},
        ]
    )

    assert warnings == [
        {
            "code": "distro_context_unconfirmed",
            "count": 2,
            "message": "SBOM does not prove distro origin for 2 matched OSV distro evidence row(s).",
        },
        {
            "code": "version_conflict",
            "count": 1,
            "message": "CPE version differs from normalized package version in 1 evidence row(s).",
        },
    ]
    assert "distro_context_unconfirmed x2" in _format_warnings(warnings)


def test_findings_html_uses_dark_grouped_soc_columns():
    component = {
        "id": "component-1",
        "name": "curl",
        "raw_version": "curl-8_0_1",
        "normalized_version": "8.0.1",
    }
    matched = {
        "versions": ["8.0.1"],
        "identities": ["cpe:/a:haxx:curl:8.0.1"],
        "match_types": ["cpe_and_package_version"],
        "confidence": "high",
        "reasons": ["version in affected range"],
        "warnings": [],
        "version_conflict": False,
        "cpe_version": "8.0.1",
        "package_version": "8.0.1",
        "cpe_version_matched": True,
        "package_version_matched": True,
        "identity_inferred": False,
        "inferred_from_repo": None,
        "distro_candidate": False,
        "ecosystem": None,
        "package_name": "curl",
    }
    decision = {
        "status": "matched_strong_evidence",
        "evidence_strength": "strong",
        "reason": "Matched with strong evidence.",
        "factors": ["SBOM CPE and normalized package version both matched."],
    }
    html = _render_findings_html(
        {
            "metadata": {
                "generated_at": "2026-08-24T10:00:00Z",
                "client": "client",
                "product": "product",
                "release": "release",
                "scan_id": "scan-1",
            },
            "counts": {
                "findings_total": 2,
                "affected_components": 1,
                "severity": {"high": 2},
            },
            "findings": [
                {
                    "component": component,
                    "matched": matched,
                    "vulnerability": {
                        "id": "CVE-2023-0001",
                        "source_advisory_ids": ["CVE-2023-0001"],
                        "severity": "high",
                        "score": 8.8,
                        "status": "active",
                        "description": "Example vulnerability.",
                        "sources": ["nvd", "cve"],
                    },
                    "decision": decision,
                },
                {
                    "component": component,
                    "matched": matched,
                    "vulnerability": {
                        "id": "CVE-2023-0002",
                        "source_advisory_ids": ["CVE-2023-0002"],
                        "severity": "high",
                        "score": 7.8,
                        "status": "active",
                        "description": "Second example vulnerability.",
                        "sources": ["nvd"],
                    },
                    "decision": decision,
                },
            ],
        }
    )

    assert "CVEX Findings" in html
    assert "--bg: #0d0f12" in html
    assert 'class="c-component">Component' in html
    assert 'class="c-sev">Risk' in html
    assert 'data-component-row="true"' in html
    assert html.count('data-component-row="true"') == 1
    assert "unique CVEs" in html
    assert 'colspan="7" class="component-row-cell"' in html
    assert "Evidence details" in html
    assert "Decision factors" in html
    assert "Matched Identity" not in html
