from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path


SOURCE_COLUMNS = ["NVD", "Debian", "Ubuntu", "Alpine", "OSV", "crates.io/RustSec", "GHSA"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare an external per-component CVE CSV with a CVEX findings CSV.")
    parser.add_argument("external_csv", type=Path, help="External per-component CSV with component and cve_list columns.")
    parser.add_argument("cvex_findings_csv", type=Path, help="CVEX findings.csv export.")
    parser.add_argument("--out-dir", type=Path, default=None, help="Output directory. Defaults to the CVEX report directory.")
    args = parser.parse_args()

    out_dir = args.out_dir or args.cvex_findings_csv.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "comparison_03_per_component.md"
    detail_path = out_dir / "comparison_03_per_component.csv"

    comparison = compare(args.external_csv, args.cvex_findings_csv)
    write_detail(detail_path, comparison)
    write_summary(summary_path, detail_path, args.external_csv, args.cvex_findings_csv, comparison)

    print(f"summary={summary_path}")
    print(f"detail_csv={detail_path}")
    print(
        " ".join(
            [
                f"external_pairs={len(comparison['external_pairs'])}",
                f"cvex_pairs={len(comparison['cvex_pairs'])}",
                f"overlap={len(comparison['common_pairs'])}",
                f"external_only={len(comparison['only_external_pairs'])}",
                f"cvex_only={len(comparison['only_cvex_pairs'])}",
            ]
        )
    )


def compare(external_path: Path, cvex_path: Path) -> dict:
    external_rows = []
    external_pairs = set()
    external_by_component: dict[str, set[str]] = defaultdict(set)
    external_meta = {}
    with external_path.open(newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            component = _norm_name(row.get("component", ""))
            cves = _parse_cves(row.get("cve_list", ""))
            external_rows.append(row)
            external_meta[component] = row
            for cve in cves:
                external_pairs.add((component, cve))
                external_by_component[component].add(cve)

    cvex_pairs = set()
    cvex_by_component: dict[str, set[str]] = defaultdict(set)
    cvex_meta = defaultdict(_empty_cvex_meta)
    with cvex_path.open(newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            component = _norm_name(row.get("component_name", ""))
            cve = (row.get("cve") or "").strip()
            if not cve:
                continue
            cvex_pairs.add((component, cve))
            cvex_by_component[component].add(cve)
            cvex_meta[component]["raw_versions"].add(row.get("raw_version") or "")
            cvex_meta[component]["normalized_versions"].add(row.get("normalized_version") or "")
            cvex_meta[component]["matched_identities"].add(row.get("matched_identity") or "")
            cvex_meta[component]["sources"].update(s.strip() for s in (row.get("sources") or "").split(",") if s.strip())
            cvex_meta[component]["confidences"][row.get("confidence") or ""] += 1
            if (row.get("version_conflict") or "").lower() == "true":
                cvex_meta[component]["version_conflicts"] += 1

    common_pairs = external_pairs & cvex_pairs
    only_external_pairs = external_pairs - cvex_pairs
    only_cvex_pairs = cvex_pairs - external_pairs
    return {
        "external_rows": external_rows,
        "external_pairs": external_pairs,
        "external_by_component": external_by_component,
        "external_meta": external_meta,
        "cvex_pairs": cvex_pairs,
        "cvex_by_component": cvex_by_component,
        "cvex_meta": cvex_meta,
        "common_pairs": common_pairs,
        "only_external_pairs": only_external_pairs,
        "only_cvex_pairs": only_cvex_pairs,
    }


def write_detail(path: Path, comparison: dict) -> None:
    fieldnames = [
        "component",
        "external_total",
        "cvex_total",
        "overlap",
        "only_external_count",
        "only_cvex_count",
        "external_version_used",
        "external_cpe_version",
        "external_version_conflict",
        "external_sources_counts",
        "cvex_raw_versions",
        "cvex_normalized_versions",
        "cvex_matched_identities",
        "cvex_sources",
        "cvex_confidences",
        "cvex_version_conflict_findings",
        "only_external_cves",
        "only_cvex_cves",
    ]
    external_by_component = comparison["external_by_component"]
    cvex_by_component = comparison["cvex_by_component"]
    external_meta = comparison["external_meta"]
    cvex_meta = comparison["cvex_meta"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for component in sorted(set(external_by_component) | set(cvex_by_component)):
            ext = external_by_component.get(component, set())
            cvx = cvex_by_component.get(component, set())
            meta = external_meta.get(component, {})
            cmeta = cvex_meta.get(component, _empty_cvex_meta())
            writer.writerow(
                {
                    "component": component,
                    "external_total": len(ext),
                    "cvex_total": len(cvx),
                    "overlap": len(ext & cvx),
                    "only_external_count": len(ext - cvx),
                    "only_cvex_count": len(cvx - ext),
                    "external_version_used": meta.get("version_used", ""),
                    "external_cpe_version": meta.get("cpe_version", ""),
                    "external_version_conflict": meta.get("version_conflict", ""),
                    "external_sources_counts": _source_counts(meta),
                    "cvex_raw_versions": _join(cmeta["raw_versions"]),
                    "cvex_normalized_versions": _join(cmeta["normalized_versions"]),
                    "cvex_matched_identities": _join(cmeta["matched_identities"]),
                    "cvex_sources": _join(cmeta["sources"]),
                    "cvex_confidences": ";".join(f"{k}={v}" for k, v in sorted(cmeta["confidences"].items()) if k),
                    "cvex_version_conflict_findings": cmeta["version_conflicts"],
                    "only_external_cves": _join(ext - cvx),
                    "only_cvex_cves": _join(cvx - ext),
                }
            )


def write_summary(summary_path: Path, detail_path: Path, external_path: Path, cvex_path: Path, comparison: dict) -> None:
    external_by_component = comparison["external_by_component"]
    cvex_by_component = comparison["cvex_by_component"]
    external_components = set(external_by_component)
    cvex_components = set(cvex_by_component)
    external_source_totals = Counter()
    for row in comparison["external_rows"]:
        for source in SOURCE_COLUMNS:
            try:
                external_source_totals[source] += int(row.get(source) or 0)
            except ValueError:
                pass

    lines = [
        "# Comparison: external per-component CSV vs CVEX findings.csv",
        "",
        f"- External report: `{external_path}`",
        f"- CVEX report: `{cvex_path}`",
        f"- Detail CSV: `{detail_path}`",
        "",
        "## Totals",
        "",
        f"- External components with CVEs: {len(external_components)}",
        f"- CVEX components with CVEs: {len(cvex_components)}",
        f"- Components in both: {len(external_components & cvex_components)}",
        f"- Components only in external: {len(external_components - cvex_components)}",
        f"- Components only in CVEX: {len(cvex_components - external_components)}",
        f"- External component/CVE pairs: {len(comparison['external_pairs'])}",
        f"- CVEX component/CVE pairs: {len(comparison['cvex_pairs'])}",
        f"- Overlapping component/CVE pairs: {len(comparison['common_pairs'])}",
        f"- External-only component/CVE pairs: {len(comparison['only_external_pairs'])}",
        f"- CVEX-only component/CVE pairs: {len(comparison['only_cvex_pairs'])}",
        "",
        "## External Source Count Totals",
        "",
    ]
    lines.extend(f"- {source}: {count}" for source, count in external_source_totals.items())
    lines.extend(["", "## Top External Gaps", "", "| component | external-only | external total | CVEX total |", "|---|---:|---:|---:|"])
    for component, gap, ext_total, cvx_total in _top_external_gaps(external_by_component, cvex_by_component):
        lines.append(f"| {component} | {gap} | {ext_total} | {cvx_total} |")
    lines.extend(["", "## Top CVEX-Only Findings", "", "| component | CVEX-only | external total | CVEX total |", "|---|---:|---:|---:|"])
    for component, extra, ext_total, cvx_total in _top_cvex_only(external_by_component, cvex_by_component):
        lines.append(f"| {component} | {extra} | {ext_total} | {cvx_total} |")
    lines.extend(["", "## Components Only In External", ""])
    lines.extend(f"- {component}: {len(external_by_component[component])} CVEs" for component in sorted(external_components - cvex_components))
    lines.extend(["", "## Components Only In CVEX", ""])
    lines.extend(f"- {component}: {len(cvex_by_component[component])} CVEs" for component in sorted(cvex_components - external_components))
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _top_external_gaps(external_by_component: dict[str, set[str]], cvex_by_component: dict[str, set[str]]) -> list[tuple[str, int, int, int]]:
    return sorted(
        (
            (component, len(external_by_component[component] - cvex_by_component.get(component, set())), len(external_by_component[component]), len(cvex_by_component.get(component, set())))
            for component in external_by_component
        ),
        key=lambda row: (-row[1], row[0]),
    )[:20]


def _top_cvex_only(external_by_component: dict[str, set[str]], cvex_by_component: dict[str, set[str]]) -> list[tuple[str, int, int, int]]:
    return sorted(
        (
            (component, len(cvex_by_component[component] - external_by_component.get(component, set())), len(external_by_component.get(component, set())), len(cvex_by_component[component]))
            for component in cvex_by_component
        ),
        key=lambda row: (-row[1], row[0]),
    )[:20]


def _empty_cvex_meta() -> dict:
    return {
        "raw_versions": set(),
        "normalized_versions": set(),
        "matched_identities": set(),
        "sources": set(),
        "confidences": Counter(),
        "version_conflicts": 0,
    }


def _norm_name(value: str | None) -> str:
    return (value or "").strip().lower()


def _parse_cves(value: str | None) -> set[str]:
    return {item.strip() for item in (value or "").split(";") if item.strip()}


def _source_counts(row: dict) -> str:
    return ";".join(f"{source}={row.get(source, '')}" for source in SOURCE_COLUMNS if row.get(source, "") not in ("", None))


def _join(values) -> str:
    return ";".join(sorted(value for value in values if value))


if __name__ == "__main__":
    main()
