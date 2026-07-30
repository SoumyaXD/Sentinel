"""Retrieval entrypoint combining exact CVE-ID lookup with semantic search."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from ingest.config import PACKAGES
from rag.chunk import chunk_cve_record


REPO_ROOT = Path(__file__).resolve().parents[1]
NORMALIZED_CVES_PATH = REPO_ROOT / "data" / "normalized" / "all_cves.json"
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
TRACKED_PACKAGES = [package["name"] for package in PACKAGES]


def _normalize_cve_id(value: str) -> str:
    return value.upper()


@lru_cache(maxsize=1)
def _normalized_record_index() -> dict[str, dict[str, Any]]:
    if not NORMALIZED_CVES_PATH.exists():
        raise FileNotFoundError(f"Normalized CVE file not found: {NORMALIZED_CVES_PATH}")

    with NORMALIZED_CVES_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, list):
        raise ValueError("Expected data/normalized/all_cves.json to contain a list of records")

    index: dict[str, dict[str, Any]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cve_id")
        if isinstance(cve_id, str) and cve_id:
            index[_normalize_cve_id(cve_id)] = item
    return index


def _chunk_id(chunk: dict[str, Any], index: int) -> str:
    metadata = chunk.get("metadata", {})
    cve_id = str(metadata.get("cve_id", "unknown_cve")).strip() or "unknown_cve"
    chunk_type = str(metadata.get("chunk_type", f"chunk_{index}")).strip() or f"chunk_{index}"
    safe_chunk_type = chunk_type.replace("/", "_").replace(":", "_").replace(" ", "_")
    return f"{cve_id}_{safe_chunk_type}"


def _enrich_chunks(chunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    seen_ids: dict[str, int] = {}

    for index, chunk in enumerate(chunks):
        base_id = _chunk_id(chunk, index)
        seen_ids[base_id] = seen_ids.get(base_id, 0) + 1
        chunk_id = base_id if seen_ids[base_id] == 1 else f"{base_id}_{seen_ids[base_id]}"
        enriched.append(
            {
                "id": chunk_id,
                "text": chunk.get("text", ""),
                "metadata": chunk.get("metadata", {}),
                "distance": None,
                "similarity": None,
            }
        )

    return enriched


def _lookup_cve_chunks(cve_id: str) -> list[dict[str, Any]]:
    record = _normalized_record_index().get(_normalize_cve_id(cve_id))
    if record is None:
        return []
    return _enrich_chunks(chunk_cve_record(record))


def _tracked_packages_mentioned(query: str) -> list[str]:
    query_lower = query.lower()
    matches = [package for package in TRACKED_PACKAGES if package.lower() in query_lower]
    return sorted(matches, key=len, reverse=True)


def _affected_package_names(metadata: dict[str, Any]) -> set[str]:
    package_names: set[str] = set()
    affected_packages = metadata.get("affected_packages", [])
    if not isinstance(affected_packages, list):
        return package_names

    for package in affected_packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if isinstance(name, str) and name:
            package_names.add(name.lower())
    return package_names


def _semantic_search(query: str, k: int) -> list[dict[str, Any]]:
    from rag.store import query as store_query

    return store_query(query, k=k)


def _rerank_package_results(results: list[dict[str, Any]], packages: list[str], k: int) -> list[dict[str, Any]]:
    if not packages:
        return results[:k]

    package_set = {package.lower() for package in packages}

    scored: list[tuple[int, float, int, dict[str, Any]]] = []
    for index, result in enumerate(results):
        metadata = result.get("metadata", {})
        match_score = 1 if isinstance(metadata, dict) and _affected_package_names(metadata) & package_set else 0
        similarity = result.get("similarity")
        sort_similarity = float(similarity) if isinstance(similarity, (int, float)) else float("-inf")
        scored.append((match_score, sort_similarity, -index, result))

    scored.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    return [item[3] for item in scored[:k]]


def _semantic_retrieve(query: str, k: int) -> list[dict[str, Any]]:
    packages = _tracked_packages_mentioned(query)
    candidate_k = k if not packages else max(k * 4, k)
    candidate_results = _semantic_search(query, k=candidate_k)
    return _rerank_package_results(candidate_results, packages, k)


def retrieve(query: str, k: int = 5) -> list[dict[str, Any]]:
    """
    Retrieve chunks for a query.

    Exact CVE IDs bypass semantic search and return every chunk for that CVE.
    Natural-language queries fall back to semantic retrieval, with a package-aware
    rerank when the query mentions one of the tracked packages.
    """

    match = CVE_ID_RE.search(query)
    if match:
        return _lookup_cve_chunks(match.group(0))
    return _semantic_retrieve(query, k)


def _print_query(label: str, query: str, k: int = 5) -> None:
    print(f"Query: {label}")
    results = retrieve(query, k=k)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"Result count: {len(results)}")
    print()


def main() -> None:
    _print_query("What is CVE-2020-28500?", "What is CVE-2020-28500?")
    _print_query("lodash regex denial of service", "lodash regex denial of service")
    _print_query("What is CVE-9999-99999?", "What is CVE-9999-99999?")
    _print_query("remote code execution vulnerability", "remote code execution vulnerability")


if __name__ == "__main__":
    main()
