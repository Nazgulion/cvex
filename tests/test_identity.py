from cvex.config import (
    CvexConfig,
    DatabaseConfig,
    DiskConfig,
    HistoryConfig,
    IdentityAliasConfig,
    LoggingConfig,
    NetworkConfig,
    PathsConfig,
    ProcessingConfig,
    SyncConfig,
    VersionOverrideConfig,
)
from cvex.db.models import SbomComponent
from cvex.identity import _apply_version_override, _trusted_override_version, infer_cpe_from_repo, normalize_repo_url


def test_normalize_github_repo_url_variants():
    assert normalize_repo_url("https://github.com/leethomason/tinyxml2.git") == "github.com/leethomason/tinyxml2"
    assert normalize_repo_url("Organization: https://github.com/tensorflow/tensorflow") == "github.com/tensorflow/tensorflow"
    assert normalize_repo_url("NONE") is None


def test_infer_cpe_from_approved_repo_alias():
    config = _config(
        {
            "github.com/tensorflow/tensorflow": IdentityAliasConfig(cpe_vendor="google", cpe_product="tensorflow"),
        }
    )

    match = infer_cpe_from_repo(config, "https://github.com/tensorflow/tensorflow", "2.9.1")

    assert match is not None
    assert match.alias_key == "github.com/tensorflow/tensorflow"
    assert match.cpe == "cpe:2.3:a:google:tensorflow:2.9.1:*:*:*:*:*:*:*"


def test_unknown_repo_does_not_infer_cpe():
    config = _config({})

    assert infer_cpe_from_repo(config, "https://github.com/example/project", "1.0.0") is None


def test_apply_trusted_version_override_to_commit_hash_component():
    component = SbomComponent(
        name="freetype",
        source_component_id="SPDXRef-SOURCE-freetype",
        raw_version="0b62c1e43dc4b0e3c50662aac757e4f7321e5466",
        normalized_version=None,
        version_status="unusable",
        version_reason="commit_hash",
    )
    config = _config(
        {},
        version_overrides=[
            VersionOverrideConfig(
                component_name="freetype",
                raw_version="0b62c1e43dc4b0e3c50662aac757e4f7321e5466",
                version="2.12.1",
                source="resolved-from-AOSP-source",
            )
        ],
    )

    changed = _apply_version_override(None, config, component)

    assert changed > 0
    assert component.normalized_version == "2.12.1"
    assert component.version_status == "usable"
    assert component.version_reason == "version_override:resolved-from-AOSP-source"


def test_version_override_requires_matching_raw_version_when_configured():
    component = SbomComponent(
        name="freetype",
        source_component_id="SPDXRef-SOURCE-freetype",
        raw_version="different",
        normalized_version=None,
        version_status="unusable",
        version_reason="commit_hash",
    )
    config = _config(
        {},
        version_overrides=[
            VersionOverrideConfig(
                component_name="freetype",
                raw_version="0b62c1e43dc4b0e3c50662aac757e4f7321e5466",
                version="2.12.1",
                source="resolved-from-AOSP-source",
            )
        ],
    )

    assert _apply_version_override(None, config, component) == 0
    assert component.normalized_version is None


def test_trusted_override_accepts_simple_numeric_versions():
    assert _trusted_override_version("112") == "112"
    assert _trusted_override_version("20221215") == "20221215"


def _config(identity_aliases, version_overrides=None):
    return CvexConfig(
        database=DatabaseConfig(url="postgresql+psycopg://cvex:cvex@postgres:5432/cvex"),
        logging=LoggingConfig(),
        history=HistoryConfig(),
        sync=SyncConfig(),
        paths=PathsConfig(),
        processing=ProcessingConfig(),
        disk=DiskConfig(),
        network=NetworkConfig(),
        attribution={},
        sources={},
        identity_aliases=identity_aliases,
        version_overrides=version_overrides or [],
    )
