from cvex.versioning import in_range, normalize_version


def test_normalizes_obvious_tags():
    assert normalize_version("curl-8_0_1").normalized == "8.0.1"
    assert normalize_version("bzip2-1.0.8").normalized == "1.0.8"
    assert normalize_version("v1.46.6").normalized == "1.46.6"


def test_rejects_hashes_and_android_build_fingerprints():
    assert normalize_version("d45ee3a2bc6271110312f01be867a9b6b91dd07f").status == "unusable"
    assert normalize_version("CompanyX/device/release-keys").status == "unusable"


def test_version_ranges():
    assert in_range("7.87.0", None, None, "8.0.0", False)
    assert not in_range("8.0.1", None, None, "8.0.0", False)
