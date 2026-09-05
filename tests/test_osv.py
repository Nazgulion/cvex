from cvex.db.models import ComponentIdentity, SbomComponent, SourceAffectedComponent
from cvex.matcher import (
    _allow_osv_package_candidate_match,
    _allow_unconfirmed_osv_distro_range,
    _component_declared_package_ecosystems,
    _component_package_names,
    _is_cve_identifier,
    _osv_version_matches,
)
from cvex.osv import _canonical_distro_cve_id, _preferred_primary_id, _published_filter_decision, _published_window


def test_osv_prefers_cve_alias_as_primary_id():
    assert _preferred_primary_id({"id": "UBUNTU-CVE-2024-0001", "aliases": ["CVE-2024-0001"]}) == "CVE-2024-0001"


def test_osv_canonicalizes_distro_cve_wrapper_ids():
    assert _preferred_primary_id({"id": "UBUNTU-CVE-2024-0001"}) == "CVE-2024-0001"
    assert _preferred_primary_id({"id": "DEBIAN-CVE-2024-0002"}) == "CVE-2024-0002"
    assert _preferred_primary_id({"id": "ALPINE-CVE-2024-0003"}) == "CVE-2024-0003"


def test_osv_keeps_non_cve_advisory_ids():
    assert _canonical_distro_cve_id("USN-1234-1") is None
    assert _preferred_primary_id({"id": "USN-1234-1"}) == "USN-1234-1"


def test_osv_published_window_includes_2017_boundary():
    start, end = _published_window(2017, 2026)

    assert _published_filter_decision({"published": "2017-01-01T00:00:00Z"}, start, end) == "include"


def test_osv_published_window_skips_before_start_year():
    start, end = _published_window(2017, 2026)

    assert _published_filter_decision({"published": "2016-12-31T23:59:59Z"}, start, end) == "outside_window"


def test_osv_published_window_skips_missing_published():
    start, end = _published_window(2017, 2026)

    assert _published_filter_decision({}, start, end) == "missing_published"


def test_osv_published_window_includes_end_year_end():
    start, end = _published_window(2017, 2026)

    assert _published_filter_decision({"published": "2026-12-31T23:59:59Z"}, start, end) == "include"
    assert _published_filter_decision({"published": "2027-01-01T00:00:00Z"}, start, end) == "outside_window"


def test_osv_fixed_range_excludes_fixed_version():
    affected = SourceAffectedComponent(
        package_name="curl",
        ecosystem="Ubuntu:22.04:LTS",
        introduced="8.0.0",
        fixed="8.0.2",
        range_type="ECOSYSTEM",
        vulnerable=True,
    )

    assert _osv_version_matches(affected, "8.0.1")
    assert not _osv_version_matches(affected, "8.0.2")


def test_osv_last_affected_range_includes_last_affected_version():
    affected = SourceAffectedComponent(
        package_name="curl",
        ecosystem="Ubuntu:22.04:LTS",
        introduced=None,
        last_affected="8.0.2",
        range_type="ECOSYSTEM",
        vulnerable=True,
    )

    assert _osv_version_matches(affected, "8.0.2")
    assert not _osv_version_matches(affected, "8.0.3")


def test_osv_exact_version_matches_only_listed_version():
    affected = SourceAffectedComponent(
        package_name="curl",
        ecosystem="Ubuntu:22.04:LTS",
        introduced="8.0.1",
        fixed="8.0.1",
        range_type="osv_exact_version",
        vulnerable=True,
    )

    assert _osv_version_matches(affected, "8.0.1")
    assert not _osv_version_matches(affected, "8.0.2")


def test_cargo_component_blocks_distro_osv_name_only_match():
    component = SbomComponent(
        name="nix",
        raw_version="0.26.2",
        normalized_version="0.26.2",
        download_location="https://static.crates.io/crates/nix/nix-0.26.2.crate",
        supplier="Organization: https://crates.io/crates/nix",
        identities=[ComponentIdentity(identity_type="package_name", identity_value="nix")],
    )

    ecosystems = _component_declared_package_ecosystems(component)

    assert ecosystems == {"cargo"}
    assert not _allow_osv_package_candidate_match("Debian:14", ecosystems)
    assert not _allow_osv_package_candidate_match("Ubuntu:24.04:LTS", ecosystems)
    assert not _allow_osv_package_candidate_match("Alpine:v3.20", ecosystems)


def test_unknown_component_provenance_allows_distro_osv_candidate_match():
    assert _allow_osv_package_candidate_match("Debian:14", set())


def test_osv_package_names_include_cpe_product_and_repo_slug():
    component = SbomComponent(
        name="libcups",
        raw_version="v2.3.3",
        normalized_version="2.3.3",
        identities=[
            ComponentIdentity(identity_type="package_name", identity_value="libcups"),
            ComponentIdentity(identity_type="cpe", identity_value="cpe:/a:cups:cups:2.3.3"),
            ComponentIdentity(identity_type="upstream_repo_url", identity_value="github.com/apple/cups"),
        ],
    )

    assert _component_package_names(component) == {"libcups", "cups"}


def test_osv_package_names_do_not_fuzzy_match_sibling_packages():
    component = SbomComponent(
        name="libcups",
        raw_version="v2.3.3",
        normalized_version="2.3.3",
        identities=[
            ComponentIdentity(identity_type="cpe", identity_value="cpe:/a:cups:cups:2.3.3"),
            ComponentIdentity(identity_type="upstream_repo_url", identity_value="github.com/apple/cups"),
        ],
    )

    names = _component_package_names(component)

    assert "cups" in names
    assert "cups-filters" not in names
    assert "libcupsfilters" not in names
    assert "cups-browsed" not in names


def test_osv_package_matching_keeps_cve_identifiers_only():
    assert _is_cve_identifier("CVE-2024-47176")
    assert not _is_cve_identifier("USN-8405-1")
    assert not _is_cve_identifier("DSA-5998-1")


def test_unconfirmed_distro_osv_range_skips_open_ended_unfixed_records():
    affected = SourceAffectedComponent(
        package_name="curl",
        ecosystem="Ubuntu:Pro:14.04:LTS",
        introduced=None,
        fixed=None,
        last_affected=None,
        range_type="ECOSYSTEM",
        vulnerable=True,
    )

    assert not _allow_unconfirmed_osv_distro_range(affected, set())


def test_unconfirmed_distro_osv_range_allows_bounded_records():
    affected = SourceAffectedComponent(
        package_name="curl",
        ecosystem="Alpine:v3.24",
        introduced="8.17.0",
        fixed="8.20.0-r0",
        range_type="ECOSYSTEM",
        vulnerable=True,
    )

    assert _allow_unconfirmed_osv_distro_range(affected, set())


def test_confirmed_distro_osv_range_allows_open_ended_records():
    affected = SourceAffectedComponent(
        package_name="curl",
        ecosystem="Debian:11",
        introduced=None,
        fixed=None,
        last_affected=None,
        range_type="ECOSYSTEM",
        vulnerable=True,
    )

    assert _allow_unconfirmed_osv_distro_range(affected, {"debian"})
