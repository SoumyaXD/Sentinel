"""Fetch and cache raw vulnerability records from the OSV API."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import requests

from ingest.config import OSV_API_BASE, PACKAGES, RAW_OSV_DIR

REQUEST_DELAY_SECONDS = 1
REQUEST_TIMEOUT_SECONDS = 60
CACHE_VERSION = 1

OSV_QUERY_URL = f"{OSV_API_BASE}/query"

PACKAGE_ECOSYSTEMS = {
    "lodash": "npm",
    "log4j-core": "Maven",
    "openssl": "generic",
    "django": "PyPI",
    "express": "npm",
    "flask": "PyPI",
    "axios": "npm",
}

PACKAGE_QUERY_METHODS = {
    "lodash": ("npm", {"package": {"name": "lodash", "ecosystem": "npm"}}),
    "log4j-core": (
        "Maven",
        {"package": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core"}},
    ),
    "django": ("PyPI", {"package": {"name": "django", "ecosystem": "PyPI"}}),
    "express": ("npm", {"package": {"name": "express", "ecosystem": "npm"}}),
    "flask": ("PyPI", {"package": {"name": "flask", "ecosystem": "PyPI"}}),
    "axios": ("npm", {"package": {"name": "axios", "ecosystem": "npm"}}),
}

OPENSSL_QUERY_CANDIDATES = [
    ("purl:pkg:generic/openssl", {"package": {"purl": "pkg:generic/openssl"}}),
    ("Debian", {"package": {"name": "openssl", "ecosystem": "Debian"}}),
    ("Alpine", {"package": {"name": "openssl", "ecosystem": "Alpine"}}),
]


def _cache_path(package_name: str) -> Path:
    return Path(RAW_OSV_DIR) / f"{package_name}.json"


def _load_cached_payload(package_name: str) -> dict[str, Any] | None:
    path = _cache_path(package_name)
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if payload.get("cache_version") != CACHE_VERSION:
        return None
    return payload


def _save_cached_payload(package_name: str, payload: dict[str, Any]) -> Path:
    path = _cache_path(package_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload_to_save = dict(payload)
    payload_to_save["cache_version"] = CACHE_VERSION
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload_to_save, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return path


def _extract_display_text(vuln: dict[str, Any]) -> str:
    summary = vuln.get("summary")
    details = vuln.get("details")
    parts = [str(part) for part in (summary, details) if part]
    return "\n\n".join(parts) if parts else str(vuln.get("id", ""))


def _sample_texts(payload: dict[str, Any], limit: int = 2) -> list[str]:
    vulns = payload.get("vulns", [])
    samples: list[str] = []
    for vuln in vulns:
        if len(samples) >= limit:
            break
        samples.append(_extract_display_text(vuln))
    return samples


def _query_osv(body: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(
        OSV_QUERY_URL,
        json=body,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()


def _paginate_query(initial_body: dict[str, Any]) -> dict[str, Any]:
    pages: list[dict[str, Any]] = []
    all_vulns: list[dict[str, Any]] = []
    body = dict(initial_body)

    while True:
        page = _query_osv(body)
        pages.append(page)
        vulns = page.get("vulns", [])
        if isinstance(vulns, list):
            all_vulns.extend(vulns)

        next_page_token = page.get("next_page_token")
        if not next_page_token:
            break

        body = dict(initial_body)
        body["page_token"] = next_page_token
        time.sleep(REQUEST_DELAY_SECONDS)

    combined = dict(pages[0]) if pages else {}
    combined["vulns"] = all_vulns
    combined["pages"] = pages
    combined["pages_fetched"] = len(pages)
    return combined


def _clean_match_exists(vulns: list[dict[str, Any]], needle: str) -> bool:
    needle_lower = needle.lower()
    for vuln in vulns[:5]:
        text = _extract_display_text(vuln).lower()
        if needle_lower in text:
            return True
    return False


def _resolve_openssl_query() -> tuple[str, dict[str, Any] | None]:
    for label, body in OPENSSL_QUERY_CANDIDATES:
        response = _paginate_query(body)
        if response.get("vulns") and _clean_match_exists(response.get("vulns", []), "openssl"):
            return label, response
    return "NO CLEAN MAPPING", None


def fetch_vulns_for_package(package_name: str, ecosystem: str) -> dict[str, Any]:
    if package_name == "openssl":
        query_method, response = _resolve_openssl_query()
        if response is None:
            return {
                "package_name": package_name,
                "query_method": query_method,
                "vulns": [],
                "pages": [],
                "pages_fetched": 0,
            }
        response["package_name"] = package_name
        response["query_method"] = query_method
        return response

    query_method, body = PACKAGE_QUERY_METHODS.get(
        package_name,
        (
            ecosystem,
            {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem,
                }
            },
        ),
    )
    response = _paginate_query(body)
    response["package_name"] = package_name
    response["query_method"] = query_method
    return response


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    for package in PACKAGES:
        package_name = package["name"]
        ecosystem = PACKAGE_ECOSYSTEMS[package_name]
        cached = _load_cached_payload(package_name)
        if cached is None:
            payload = fetch_vulns_for_package(package_name, ecosystem)
            _save_cached_payload(package_name, payload)
        else:
            payload = cached

        samples = _sample_texts(payload, limit=2)
        print(f"--- {package_name} ---")
        print(f"Query method used: {payload.get('query_method', ecosystem)}")
        print(f"Total vulnerabilities: {len(payload.get('vulns', []))}")
        for index, sample in enumerate(samples, start=1):
            print(f"Sample {index}: {sample}")
        print()


if __name__ == "__main__":
    main()
