"""Legacy parser helpers only.

CVEX v2 has no OSV connector, storage, CLI option, or worker.  These pure helpers
remain temporarily importable for consumers migrating old watchlist tooling.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from cvex.util import parse_dt


def _canonical_distro_cve_id(value: str | None) -> str | None:
    match = re.fullmatch(r"(?:UBUNTU|DEBIAN|ALPINE)-(CVE-\d{4}-\d+)", value or "", re.IGNORECASE)
    return match.group(1).upper() if match else None


def _preferred_primary_id(payload: dict[str, Any]) -> str | None:
    for alias in payload.get("aliases") or []:
        if isinstance(alias, str) and alias.upper().startswith("CVE-"):
            return alias.upper()
    return _canonical_distro_cve_id(payload.get("id")) or payload.get("id")


def _published_window(start_year: int, end_year: int):
    return datetime(start_year, 1, 1, tzinfo=timezone.utc), datetime(end_year, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)


def _published_filter_decision(payload: dict[str, Any], start, end) -> str:
    published = parse_dt(payload.get("published"))
    if published is None:
        return "missing_published"
    return "include" if start <= published <= end else "outside_window"
