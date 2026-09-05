from __future__ import annotations

import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

SHA_RE = re.compile(r"^[0-9a-f]{7,64}$", re.IGNORECASE)
VERSION_RE = re.compile(r"(?<![A-Za-z0-9])(?P<version>v?\d+(?:[._-]\d+)+(?:[._-]?[A-Za-z0-9]+)?)")


@dataclass(frozen=True)
class NormalizedVersion:
    raw: str | None
    normalized: str | None
    status: str
    reason: str | None


def normalize_version(raw: str | None) -> NormalizedVersion:
    if raw is None or raw == "":
        return NormalizedVersion(raw, None, "unusable", "missing_version")
    value = raw.strip()
    lowered = value.lower()
    if "release-keys" in lowered or "/user/" in lowered or ":" in value and "/" in value:
        return NormalizedVersion(raw, None, "unusable", "android_build_fingerprint")
    if SHA_RE.match(value):
        return NormalizedVersion(raw, None, "unusable", "commit_hash")

    match = VERSION_RE.search(value)
    if not match:
        return NormalizedVersion(raw, None, "unusable", "no_version_pattern")

    normalized = match.group("version")
    if normalized.startswith("v"):
        normalized = normalized[1:]
    normalized = normalized.replace("_", ".").replace("-", ".")
    return NormalizedVersion(raw, normalized, "usable", None)


def compare_versions(left: str, right: str) -> int:
    try:
        left_v = Version(left)
        right_v = Version(right)
        return (left_v > right_v) - (left_v < right_v)
    except InvalidVersion:
        return (left > right) - (left < right)


def in_range(
    version: str,
    start: str | None,
    start_inclusive: bool | None,
    end: str | None,
    end_inclusive: bool | None,
) -> bool:
    if start:
        cmp_start = compare_versions(version, start)
        if start_inclusive is False and cmp_start <= 0:
            return False
        if start_inclusive is not False and cmp_start < 0:
            return False
    if end:
        cmp_end = compare_versions(version, end)
        if end_inclusive is True and cmp_end > 0:
            return False
        if end_inclusive is not True and cmp_end >= 0:
            return False
    return True
