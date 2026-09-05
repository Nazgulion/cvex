from pathlib import Path

from cvex.cve import _cve_id, _is_cve_record_path


def test_cve_record_path_filter_excludes_delta_metadata():
    assert _is_cve_record_path(Path("cves/2026/78xxx/CVE-2026-78213.json"))
    assert not _is_cve_record_path(Path("cves/delta.json"))
    assert not _is_cve_record_path(Path("cves/deltaLog.json"))


def test_cve_id_ignores_non_record_json_payloads():
    assert _cve_id([]) is None
