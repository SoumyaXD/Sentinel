"""Chunk normalized CVE records into embeddable text units."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
NORMALIZED_CVES_PATH = REPO_ROOT / "data" / "normalized" / "all_cves.json"

MARKDOWN_HEADING_RE = re.compile(r"^(#{1,6})\s+(?P<title>.+?)\s*$")
PLAIN_SECTION_RE = re.compile(
    r"^(?P<title>(?:steps to reproduce|impact|fix|recommendation|workaround|mitigation|details|analysis|description|proof of concept|poc|credits|references))[:\s-]*$",
    re.IGNORECASE,
)
WHITESPACE_RE = re.compile(r"\s+")
ALNUM_RE = re.compile(r"[^a-z0-9]+")


def _load_normalized_records() -> list[dict[str, Any]]:
    if not NORMALIZED_CVES_PATH.exists():
        raise FileNotFoundError(f"Normalized CVE file not found: {NORMALIZED_CVES_PATH}")

    with NORMALIZED_CVES_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, list):
        raise ValueError("Expected data/normalized/all_cves.json to contain a list of records")

    records: list[dict[str, Any]] = []
    for item in payload:
        if isinstance(item, dict):
            records.append(item)
    return records


def _score_context(record: dict[str, Any]) -> str:
    score = record.get("cvss_score")
    severity = record.get("cvss_severity")

    if score is None and not severity:
        return "CVSS unknown"

    parts: list[str] = []
    if score is not None:
        try:
            parts.append(f"{float(score):g}")
        except (TypeError, ValueError):
            parts.append(str(score))
    if severity:
        parts.append(str(severity).upper())

    return "CVSS " + ", ".join(parts) if parts else "CVSS unknown"


def _cleanup_text(text: str) -> str:
    cleaned = text.replace("\u2060", "").replace("\u00a0", " ")
    cleaned = WHITESPACE_RE.sub(" ", cleaned)
    return cleaned.strip()


def _format_version_range(version_range: dict[str, Any]) -> str:
    introduced = str(version_range.get("introduced", "")).strip() or None
    fixed = str(version_range.get("fixed", "")).strip() or None
    last_affected = str(version_range.get("last_affected", "")).strip() or None

    if introduced and fixed:
        if introduced == fixed:
            return f"version {introduced}"
        return f"versions {introduced} through {fixed}"
    if introduced and last_affected:
        if introduced == last_affected:
            return f"version {introduced}"
        return f"versions {introduced} through {last_affected}"
    if introduced:
        return f"versions starting at {introduced}"
    if fixed:
        return f"versions before {fixed}"
    if last_affected:
        return f"versions through {last_affected}"
    return ""


def _format_affected_packages(record: dict[str, Any]) -> str:
    packages = record.get("affected_packages", [])
    if not isinstance(packages, list) or not packages:
        return ""

    package_phrases: list[str] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = str(package.get("name", "")).strip()
        ecosystem = str(package.get("ecosystem", "")).strip()
        version_ranges = package.get("version_ranges", [])

        if not name and not ecosystem:
            continue

        label = name or "package"
        if ecosystem:
            label = f"{label} ({ecosystem})"

        if isinstance(version_ranges, list) and version_ranges:
            versions = [
                _format_version_range(version_range)
                for version_range in version_ranges
                if isinstance(version_range, dict)
            ]
            versions = [version for version in versions if version]
            if versions:
                package_phrases.append(f"{label} {', '.join(versions)}")
                continue

        package_phrases.append(label)

    if not package_phrases:
        return ""

    if len(package_phrases) == 1:
        return f"Affects {package_phrases[0]}."

    return "Affects " + "; ".join(package_phrases) + "."


def _normalize_section_name(title: str, fallback: str) -> str:
    normalized = ALNUM_RE.sub("_", title.lower()).strip("_")
    return normalized or fallback


def _is_code_fence(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("```") or stripped.startswith("~~~")


def _split_into_sections(text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    sections: list[tuple[str, list[str]]] = []
    current_title = "intro"
    current_lines: list[str] = []
    seen_heading = False
    in_code_block = False

    def flush() -> None:
        nonlocal current_lines, current_title
        chunk_text = "\n".join(current_lines).strip()
        if chunk_text:
            sections.append((current_title, current_lines.copy()))
        current_lines = []

    for line in lines:
        if _is_code_fence(line):
            in_code_block = not in_code_block
            current_lines.append(line)
            continue

        heading_match = None
        if not in_code_block:
            heading_match = MARKDOWN_HEADING_RE.match(line.strip())
            if heading_match is None:
                plain_match = PLAIN_SECTION_RE.match(line.strip())
                if plain_match:
                    heading_match = plain_match

        if heading_match is not None and not in_code_block:
            flush()
            seen_heading = True
            current_title = heading_match.group("title").strip()
            current_lines = []
            continue

        current_lines.append(line)

    flush()

    if not seen_heading:
        return []

    return [(_normalize_section_name(title, f"section_{index + 1}"), "\n".join(lines).strip()) for index, (title, lines) in enumerate(sections) if "\n".join(lines).strip()]


def _split_paragraphs(text: str) -> list[tuple[str, str]]:
    blocks: list[list[str]] = []
    current: list[str] = []
    in_code_block = False

    def flush() -> None:
        if current:
            block = "\n".join(current).strip()
            if block:
                blocks.append([block])
            current.clear()

    for line in text.splitlines():
        stripped = line.strip()
        if _is_code_fence(line):
            current.append(line)
            in_code_block = not in_code_block
            continue
        if not in_code_block and not stripped:
            flush()
            continue
        current.append(line)

    flush()

    paragraphs = [block[0] for block in blocks]
    if len(paragraphs) <= 1:
        return []
    return [(f"paragraph_{index + 1}", paragraph) for index, paragraph in enumerate(paragraphs)]


def _looks_rich_osv_description(record: dict[str, Any], description: str) -> bool:
    sources = record.get("sources", [])
    if not isinstance(sources, list) or "osv" not in sources:
        return False
    if len(description) > 500:
        return True
    if "\n\n" in description:
        return True
    if "```" in description or "~~~" in description:
        return True
    for line in description.splitlines():
        if MARKDOWN_HEADING_RE.match(line.strip()) or PLAIN_SECTION_RE.match(line.strip()):
            return True
    return False


def _build_chunk_text(
    record: dict[str, Any],
    body: str,
    *,
    chunk_label: str | None = None,
) -> str:
    cve_id = str(record.get("cve_id", "")).strip() or "UNKNOWN-CVE"
    prefix = f"{cve_id} ({_score_context(record)}):"
    sections = [prefix]
    if chunk_label:
        sections.append(f"{chunk_label}.")
    if body:
        sections.append(body.strip())

    affected_summary = _format_affected_packages(record)
    if affected_summary:
        sections.append(affected_summary)

    return _cleanup_text(" ".join(sections))


def _build_metadata(record: dict[str, Any], chunk_type: str) -> dict[str, Any]:
    affected_packages = []
    packages = record.get("affected_packages", [])
    if isinstance(packages, list):
        for package in packages:
            if not isinstance(package, dict):
                continue
            affected_packages.append(
                {
                    "name": str(package.get("name", "")).strip(),
                    "ecosystem": str(package.get("ecosystem", "")).strip(),
                }
            )

    metadata: dict[str, Any] = {
        "cve_id": record.get("cve_id"),
        "cvss_score": record.get("cvss_score"),
        "cvss_severity": record.get("cvss_severity"),
        "affected_packages": affected_packages,
        "chunk_type": chunk_type,
    }
    if chunk_type.startswith("section:"):
        metadata["section_name"] = chunk_type.split(":", 1)[1]
    return metadata


def chunk_cve_record(record: dict[str, Any]) -> list[dict[str, Any]]:
    raw_description = str(record.get("description", ""))
    if not raw_description.strip():
        return []

    cleaned_description = _cleanup_text(raw_description)

    if record.get("sources") == ["nvd"] or not _looks_rich_osv_description(record, raw_description):
        text = _build_chunk_text(record, cleaned_description)
        return [
            {
                "text": text,
                "metadata": _build_metadata(record, "full"),
            }
        ]

    section_chunks = _split_into_sections(raw_description)
    if not section_chunks:
        section_chunks = _split_paragraphs(raw_description)

    if not section_chunks:
        text = _build_chunk_text(record, cleaned_description)
        return [
            {
                "text": text,
                "metadata": _build_metadata(record, "full"),
            }
        ]

    chunks: list[dict[str, Any]] = []
    for index, (section_name, section_body) in enumerate(section_chunks, start=1):
        chunk_type = f"section:{section_name}"
        chunk_text = _build_chunk_text(record, section_body, chunk_label=section_name.replace("_", " "))
        chunks.append(
            {
                "text": chunk_text,
                "metadata": _build_metadata(record, chunk_type),
            }
        )

    return chunks


def chunk_all_cve_records(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    chunks: list[dict[str, Any]] = []
    stats = {
        "single_chunk_cves": 0,
        "multi_section_cves": 0,
    }

    for record in records:
        record_chunks = chunk_cve_record(record)
        chunks.extend(record_chunks)
        if len(record_chunks) > 1:
            stats["multi_section_cves"] += 1
        elif len(record_chunks) == 1:
            stats["single_chunk_cves"] += 1

    return chunks, stats


def main() -> None:
    records = _load_normalized_records()
    chunks, stats = chunk_all_cve_records(records)
    chunk_type_counts = Counter(chunk["metadata"]["chunk_type"] for chunk in chunks if isinstance(chunk, dict))

    print(f"Total CVEs processed: {len(records)}")
    print(f"Total chunks produced: {len(chunks)}")
    print(f"Single-chunk CVEs: {stats['single_chunk_cves']}")
    print(f"Multi-section CVEs: {stats['multi_section_cves']}")
    print("Chunk type breakdown:")
    for chunk_type, count in sorted(chunk_type_counts.items()):
        print(f"  {chunk_type}: {count}")


if __name__ == "__main__":
    main()
