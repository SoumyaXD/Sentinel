"""Normalize cached NVD and OSV records into a unified per-CVE schema."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Any

from ingest.config import NORMALIZED_DIR, PACKAGES, RAW_NVD_DIR, RAW_OSV_DIR

PACKAGE_ECOSYSTEMS = {package["name"]: package["ecosystem"] for package in PACKAGES}
NVD_PRIMARY_PRODUCT_ALIASES = {
    "log4j-core": "log4j",
}

NVD_CVSS_PRIORITY = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_path(relative_path: str) -> Path:
    return _repo_root() / relative_path


def _read_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return payload if isinstance(payload, dict) else {}


def _normalize_ecosystem(value: Any) -> str:
    if not value:
        return ""
    return str(value).strip().lower()


def _parse_date(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).date().isoformat()
    except ValueError:
        try:
            return date.fromisoformat(text[:10]).isoformat()
        except ValueError:
            return None


def _first_english_description(descriptions: Any) -> str:
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if not isinstance(item, dict):
            continue
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"]).strip()
    return ""


def _nvd_description(cve: dict[str, Any]) -> str:
    return _first_english_description(cve.get("descriptions", []))


def _osv_description(vuln: dict[str, Any]) -> str:
    summary = str(vuln.get("summary", "")).strip()
    details = str(vuln.get("details", "")).strip()
    parts = [part for part in (summary, details) if part]
    return "\n\n".join(parts)


def _nvd_cvss_metric(cve: dict[str, Any]) -> dict[str, Any] | None:
    metrics = cve.get("metrics", {})
    if not isinstance(metrics, dict):
        return None
    for key in NVD_CVSS_PRIORITY:
        candidates = metrics.get(key, [])
        if not isinstance(candidates, list):
            continue
        for metric in candidates:
            if not isinstance(metric, dict):
                continue
            cvss_data = metric.get("cvssData", {})
            if isinstance(cvss_data, dict) and cvss_data:
                return cvss_data
    return None


def _nvd_cvss_summary(cve: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics", {})
    if not isinstance(metrics, dict):
        return None, None, None

    for key in NVD_CVSS_PRIORITY:
        candidates = metrics.get(key, [])
        if not isinstance(candidates, list):
            continue
        for metric in candidates:
            if not isinstance(metric, dict):
                continue
            cvss_data = metric.get("cvssData", {})
            if not isinstance(cvss_data, dict) or not cvss_data:
                continue

            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            severity = metric.get("baseSeverity") if key == "cvssMetricV2" else cvss_data.get("baseSeverity")

            parsed_score: float | None = None
            if score is not None:
                try:
                    parsed_score = float(score)
                except (TypeError, ValueError):
                    parsed_score = None

            return (
                parsed_score,
                str(vector) if vector else None,
                str(severity).upper() if severity else None,
            )

    return None, None, None


def _nvd_references(cve: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()
    for item in cve.get("references", []):
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not url:
            continue
        text = str(url).strip()
        if text and text not in seen:
            seen.add(text)
            refs.append(text)
    return refs


def _osv_references(vuln: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()
    for item in vuln.get("references", []):
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not url:
            continue
        text = str(url).strip()
        if text and text not in seen:
            seen.add(text)
            refs.append(text)
    return refs


def _cpe_product_name(criteria: str, fallback: str) -> str:
    parts = criteria.split(":")
    if len(parts) > 4 and parts[4] not in {"*", "-"}:
        return parts[4]
    return fallback


def _primary_nvd_product_name(package_name: str) -> str:
    return NVD_PRIMARY_PRODUCT_ALIASES.get(package_name, package_name)


def _nvd_version_range(cpe_match: dict[str, Any]) -> dict[str, str] | None:
    if not isinstance(cpe_match, dict):
        return None

    introduced = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
    fixed = cpe_match.get("versionEndExcluding") or cpe_match.get("versionEndIncluding")

    criteria = str(cpe_match.get("criteria", "")).strip()
    if not introduced and not fixed:
        parts = criteria.split(":")
        if len(parts) > 5 and parts[5] not in {"*", "-"}:
            version = parts[5]
            return {"introduced": version, "fixed": version}
        return None

    range_record: dict[str, str] = {}
    if introduced:
        range_record["introduced"] = str(introduced)
    if fixed:
        range_record["fixed"] = str(fixed)
    return range_record or None


def _nvd_affected_packages(
    cve: dict[str, Any],
    package_name: str,
    ecosystem: str,
) -> list[dict[str, Any]]:
    primary_product_name = _primary_nvd_product_name(package_name)
    version_ranges: list[dict[str, Any]] = []
    configurations = cve.get("configurations", [])
    if not isinstance(configurations, list):
        return []

    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        for node in configuration.get("nodes", []):
            if not isinstance(node, dict):
                continue
            for cpe_match in node.get("cpeMatch", []):
                if not isinstance(cpe_match, dict) or not cpe_match.get("vulnerable", False):
                    continue
                criteria = str(cpe_match.get("criteria", "")).strip()
                product_name = _cpe_product_name(criteria, package_name)
                if product_name != primary_product_name:
                    continue
                range_record = _nvd_version_range(cpe_match)
                if range_record and range_record not in version_ranges:
                    version_ranges.append(range_record)

    return [
        {
            "name": package_name,
            "ecosystem": ecosystem,
            "version_ranges": version_ranges,
        }
    ]


def _osv_version_ranges(events: Any) -> list[dict[str, Any]]:
    if not isinstance(events, list):
        return []

    version_ranges: list[dict[str, Any]] = []
    current_introduced: str | None = None

    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("introduced") is not None:
            if current_introduced is not None:
                version_ranges.append({"introduced": current_introduced})
            current_introduced = str(event["introduced"])
            continue
        if event.get("fixed") is not None:
            if current_introduced is None:
                version_ranges.append({"fixed": str(event["fixed"])})
            else:
                version_ranges.append(
                    {
                        "introduced": current_introduced,
                        "fixed": str(event["fixed"]),
                    }
                )
                current_introduced = None
            continue
        if event.get("last_affected") is not None:
            if current_introduced is None:
                version_ranges.append({"last_affected": str(event["last_affected"])})
            else:
                version_ranges.append(
                    {
                        "introduced": current_introduced,
                        "last_affected": str(event["last_affected"]),
                    }
                )
                current_introduced = None

    if current_introduced is not None:
        version_ranges.append({"introduced": current_introduced})

    return version_ranges


def _osv_affected_packages(vuln: dict[str, Any]) -> list[dict[str, Any]]:
    affected_packages: dict[tuple[str, str], dict[str, Any]] = {}
    affected = vuln.get("affected", [])
    if not isinstance(affected, list):
        return []

    for entry in affected:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package", {})
        if not isinstance(package, dict):
            package = {}
        name = str(package.get("name") or "").strip()
        ecosystem = _normalize_ecosystem(package.get("ecosystem"))
        key = (name, ecosystem)
        package_entry = affected_packages.setdefault(
            key,
            {
                "name": name,
                "ecosystem": ecosystem,
                "version_ranges": [],
            },
        )

        for range_item in entry.get("ranges", []):
            if not isinstance(range_item, dict):
                continue
            for version_range in _osv_version_ranges(range_item.get("events", [])):
                if version_range not in package_entry["version_ranges"]:
                    package_entry["version_ranges"].append(version_range)

    return list(affected_packages.values())


def _merge_references(*source_lists: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for source_list in source_lists:
        for item in source_list:
            if item and item not in seen:
                seen.add(item)
                merged.append(item)
    return merged


def _best_osv_description(vulns: list[dict[str, Any]]) -> str:
    best = ""
    for vuln in vulns:
        text = _osv_description(vuln)
        if len(text) > len(best):
            best = text
    return best


def _merge_affected_packages(
    nvd_records: list[dict[str, Any]],
    osv_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    packages: dict[tuple[str, str], dict[str, Any]] = {}

    for record in osv_records:
        for package in _osv_affected_packages(record):
            key = (package["name"], package["ecosystem"])
            entry = packages.setdefault(
                key,
                {
                    "name": package["name"],
                    "ecosystem": package["ecosystem"],
                    "version_ranges": [],
                },
            )
            for version_range in package.get("version_ranges", []):
                if version_range not in entry["version_ranges"]:
                    entry["version_ranges"].append(version_range)

    for record in nvd_records:
        package_name = record["package_name"]
        ecosystem = record["ecosystem"]
        for package in _nvd_affected_packages(record["cve"], package_name, ecosystem):
            key = (package["name"], package["ecosystem"])
            entry = packages.setdefault(
                key,
                {
                    "name": package["name"],
                    "ecosystem": package["ecosystem"],
                    "version_ranges": [],
                },
            )
            for version_range in package.get("version_ranges", []):
                if version_range not in entry["version_ranges"]:
                    entry["version_ranges"].append(version_range)

    return list(packages.values())


def _load_nvd_index() -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    raw_dir = _resolve_path(RAW_NVD_DIR)
    for path in sorted(raw_dir.glob("*.json")):
        package_name = path.stem
        ecosystem = _normalize_ecosystem(PACKAGE_ECOSYSTEMS.get(package_name, ""))
        payload = _read_json_file(path)
        for vuln in payload.get("vulnerabilities", []):
            if not isinstance(vuln, dict):
                continue
            cve = vuln.get("cve", {})
            if not isinstance(cve, dict):
                continue
            cve_id = cve.get("id")
            if not cve_id:
                continue
            index[str(cve_id)].append(
                {
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "cve": cve,
                }
            )
    return index


def _load_osv_index() -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    raw_dir = _resolve_path(RAW_OSV_DIR)
    for path in sorted(raw_dir.glob("*.json")):
        payload = _read_json_file(path)
        for vuln in payload.get("vulns", []):
            if not isinstance(vuln, dict):
                continue
            aliases = vuln.get("aliases", [])
            if not isinstance(aliases, list):
                continue
            cve_aliases = [alias for alias in aliases if isinstance(alias, str) and alias.startswith("CVE-")]
            if not cve_aliases:
                continue
            for cve_id in cve_aliases:
                index[cve_id].append(
                    {
                        "package_name": path.stem,
                        "ecosystem": "",
                        "vuln": vuln,
                    }
                )
    return index


def _choose_description(nvd_records: list[dict[str, Any]], osv_records: list[dict[str, Any]]) -> str:
    osv_description = _best_osv_description([record["vuln"] for record in osv_records])
    if osv_description:
        return osv_description
    for record in nvd_records:
        description = _nvd_description(record["cve"])
        if description:
            return description
    return ""


def _choose_published_date(nvd_records: list[dict[str, Any]], osv_records: list[dict[str, Any]]) -> str | None:
    for record in nvd_records:
        published = _parse_date(record["cve"].get("published"))
        if published:
            return published
    for record in osv_records:
        published = _parse_date(record["vuln"].get("published"))
        if published:
            return published
    return None


def _choose_cvss(nvd_records: list[dict[str, Any]]) -> tuple[float | None, str | None, str | None]:
    for record in nvd_records:
        score, vector, severity = _nvd_cvss_summary(record["cve"])
        if score is not None or vector is not None or severity is not None:
            return score, vector, severity
    return None, None, None


def _choose_references(nvd_records: list[dict[str, Any]], osv_records: list[dict[str, Any]]) -> list[str]:
    nvd_refs: list[str] = []
    for record in nvd_records:
        nvd_refs.extend(_nvd_references(record["cve"]))
    osv_refs: list[str] = []
    for record in osv_records:
        osv_refs.extend(_osv_references(record["vuln"]))
    return _merge_references(nvd_refs, osv_refs)


def _normalize_record(
    cve_id: str,
    nvd_records: list[dict[str, Any]],
    osv_records: list[dict[str, Any]],
) -> dict[str, Any]:
    description = _choose_description(nvd_records, osv_records)
    cvss_score, cvss_vector, cvss_severity = _choose_cvss(nvd_records)
    published_date = _choose_published_date(nvd_records, osv_records)
    affected_packages = _merge_affected_packages(nvd_records, osv_records)
    references = _choose_references(nvd_records, osv_records)

    sources: list[str] = []
    if nvd_records:
        sources.append("nvd")
    if osv_records:
        sources.append("osv")

    normalized: dict[str, Any] = {
        "cve_id": cve_id,
        "description": description,
        "affected_packages": affected_packages,
        "references": references,
        "sources": sources,
    }
    if cvss_score is not None:
        normalized["cvss_score"] = cvss_score
    if cvss_vector:
        normalized["cvss_vector"] = cvss_vector
    if cvss_severity:
        normalized["cvss_severity"] = cvss_severity
    if published_date:
        normalized["published_date"] = published_date

    return normalized


def normalize_records() -> list[dict[str, Any]]:
    nvd_index = _load_nvd_index()
    osv_index = _load_osv_index()
    all_cve_ids = sorted(set(nvd_index) | set(osv_index))
    normalized_records: list[dict[str, Any]] = []

    for cve_id in all_cve_ids:
        normalized_records.append(
            _normalize_record(
                cve_id,
                nvd_index.get(cve_id, []),
                osv_index.get(cve_id, []),
            )
        )

    return normalized_records


def _save_normalized_records(records: list[dict[str, Any]]) -> Path:
    output_dir = _resolve_path(NORMALIZED_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "all_cves.json"
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(records, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return output_path


def main() -> None:
    records = normalize_records()
    output_path = _save_normalized_records(records)

    nvd_index = _load_nvd_index()
    osv_index = _load_osv_index()
    nvd_only = len(set(nvd_index) - set(osv_index))
    osv_only = len(set(osv_index) - set(nvd_index))
    merged = len(set(nvd_index) & set(osv_index))

    print(f"Total CVEs processed: {len(records)}")
    print(f"NVD-only: {nvd_only}")
    print(f"OSV-only: {osv_only}")
    print(f"Merged from both: {merged}")
    print(f"Saved normalized records to: {output_path}")


if __name__ == "__main__":
    main()
