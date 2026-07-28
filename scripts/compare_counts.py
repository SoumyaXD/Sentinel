from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ingest.config import PACKAGES, RAW_NVD_DIR, RAW_OSV_DIR


def _count_entries(path: Path, key: str) -> int:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    values = payload.get(key, [])
    return len(values) if isinstance(values, list) else 0


def main() -> None:
    print("Package       | NVD count | OSV count")
    print("------------- | --------- | ---------")
    for package in PACKAGES:
        name = package["name"]
        nvd_count = _count_entries(Path(RAW_NVD_DIR) / f"{name}.json", "vulnerabilities")
        osv_count = _count_entries(Path(RAW_OSV_DIR) / f"{name}.json", "vulns")
        print(f"{name:<13} | {nvd_count:<9} | {osv_count}")


if __name__ == "__main__":
    main()
