from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote


@dataclass(frozen=True)
class ParsedCpe:
    raw: str
    version: str
    part: str | None
    vendor: str | None
    product: str | None
    component_version: str | None


def _clean(value: str | None) -> str | None:
    if value in (None, "", "*", "-"):
        return None
    return unquote(value.replace("\\:", ":"))


def parse_cpe(raw: str | None) -> ParsedCpe | None:
    if not raw:
        return None
    if raw.startswith("cpe:/"):
        parts = raw[len("cpe:/") :].split(":")
        while len(parts) < 4:
            parts.append("")
        return ParsedCpe(
            raw=raw,
            version="2.2",
            part=_clean(parts[0]),
            vendor=_clean(parts[1]),
            product=_clean(parts[2]),
            component_version=_clean(parts[3]),
        )
    if raw.startswith("cpe:2.3:"):
        parts = raw.split(":")
        while len(parts) < 6:
            parts.append("")
        return ParsedCpe(
            raw=raw,
            version="2.3",
            part=_clean(parts[2]),
            vendor=_clean(parts[3]),
            product=_clean(parts[4]),
            component_version=_clean(parts[5]),
        )
    return None


def same_product(left: ParsedCpe, right: ParsedCpe) -> bool:
    return (
        left.part == right.part
        and left.vendor == right.vendor
        and left.product == right.product
    )
