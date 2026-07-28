"""Fetch and cache raw CVE records from the NVD API."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

from ingest.config import NVD_API_BASE, PACKAGES, RAW_NVD_DIR

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip() or None
REQUEST_DELAY_SECONDS = 1 if NVD_API_KEY else 6
REQUEST_TIMEOUT_SECONDS = 60
PACKAGE_CPE_MATCHES = {
    "lodash": "cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*",
    "log4j-core": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
    "openssl": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
    "django": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    "express": "cpe:2.3:a:openjsf:express:*:*:*:*:*:node.js:*:*",
    "flask": "cpe:2.3:a:palletsprojects:flask:*:*:*:*:*:*:*:*",
    "axios": "cpe:2.3:a:axios:axios:*:*:*:*:*:node.js:*:*",
}


def _build_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def _fetch_page(package_name: str, start_index: int) -> dict[str, Any]:
    cpe_match = PACKAGE_CPE_MATCHES.get(package_name)
    params = {
        "startIndex": start_index,
    }
    if cpe_match:
        # Prefer NVD's product classification over free-text search.
        params["virtualMatchString"] = cpe_match
    else:
        # Weaker fallback: only use keyword search when a clean CPE match is unavailable.
        params["keywordSearch"] = package_name
        print(f"[fallback keywordSearch] {package_name} has no clean CPE match; using broader text search")
    response = requests.get(
        NVD_API_BASE,
        headers=_build_headers(),
        params=params,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()


def fetch_cves_for_package(package_name: str) -> dict[str, Any]:
    pages: list[dict[str, Any]] = []
    all_vulnerabilities: list[dict[str, Any]] = []
    total_results = 0
    results_per_page = 0
    start_index = 0

    while True:
        page = _fetch_page(package_name, start_index)
        pages.append(page)

        if not total_results:
            total_results = int(page.get("totalResults", 0) or 0)
        if not results_per_page:
            results_per_page = int(page.get("resultsPerPage", 0) or 0)

        vulnerabilities = page.get("vulnerabilities", [])
        if isinstance(vulnerabilities, list):
            all_vulnerabilities.extend(vulnerabilities)

        fetched_count = len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
        if fetched_count == 0 or len(all_vulnerabilities) >= total_results:
            break

        start_index += fetched_count
        time.sleep(REQUEST_DELAY_SECONDS)

    combined_response: dict[str, Any] = dict(pages[0]) if pages else {}
    combined_response["resultsPerPage"] = results_per_page
    combined_response["totalResults"] = total_results
    combined_response["vulnerabilities"] = all_vulnerabilities
    combined_response["pagesFetched"] = len(pages)
    combined_response["rawPages"] = pages
    return combined_response


def _save_raw_response(package_name: str, payload: dict[str, Any]) -> Path:
    output_dir = Path(RAW_NVD_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{package_name}.json"
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return output_path


def _sample_descriptions(payload: dict[str, Any], limit: int = 2) -> list[str]:
    samples: list[str] = []
    for vulnerability in payload.get("vulnerabilities", []):
        if len(samples) >= limit:
            break
        cve = vulnerability.get("cve", {})
        for description in cve.get("descriptions", []):
            if description.get("lang") == "en" and description.get("value"):
                samples.append(description["value"])
                break
    return samples


def main() -> None:
    for package in PACKAGES:
        package_name = package["name"]
        response = fetch_cves_for_package(package_name)
        _save_raw_response(package_name, response)
        cve_count = len(response.get("vulnerabilities", []))
        match_string = PACKAGE_CPE_MATCHES.get(package_name)
        match_label = match_string if match_string else "FALLBACK: keywordSearch"
        print(f"package: {package_name}")
        print(f"cpe match used: {match_label}")
        print(f"total CVE count: {cve_count}")
        for index, description in enumerate(_sample_descriptions(response), start=1):
            print(f"sample {index}: {description}")
        print()


if __name__ == "__main__":
    main()
