from cvex.db.models import SourceAffectedComponent
from cvex.matcher import _affected_version_match, _cap_confidence, _version_confidence


def test_version_conflict_keeps_cpe_only_match_with_medium_confidence():
    affected = SourceAffectedComponent(
        cpe_version="7.87.0",
        vulnerable=True,
    )

    match = _affected_version_match(affected, "7.87.0", "8.0.1")

    assert match.any_matched
    assert match.version_conflict
    assert match.cpe_version_matched
    assert not match.package_version_matched
    assert match.matched_version == "7.87.0"
    assert match.match_type == "cpe_version"
    assert _version_confidence("usable", match) == "medium"


def test_version_conflict_uses_high_confidence_when_both_versions_match_range():
    affected = SourceAffectedComponent(
        version_start="7.0.0",
        start_inclusive=True,
        version_end="9.0.0",
        end_inclusive=False,
        vulnerable=True,
    )

    match = _affected_version_match(affected, "7.87.0", "8.0.1")

    assert match.any_matched
    assert match.version_conflict
    assert match.cpe_version_matched
    assert match.package_version_matched
    assert match.matched_version == "7.87.0; 8.0.1"
    assert match.match_type == "cpe_and_package_version"
    assert _version_confidence("usable", match) == "high"


def test_version_conflict_drops_candidate_when_neither_version_matches():
    affected = SourceAffectedComponent(
        version_start="6.0.0",
        start_inclusive=True,
        version_end="7.0.0",
        end_inclusive=False,
        vulnerable=True,
    )

    match = _affected_version_match(affected, "7.87.0", "8.0.1")

    assert not match.any_matched
    assert not match.cpe_version_matched
    assert not match.package_version_matched


def test_inferred_identity_caps_high_version_confidence_to_medium():
    assert _cap_confidence("high", "medium") == "medium"
