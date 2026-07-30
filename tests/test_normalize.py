from __future__ import annotations

import unittest

from ingest.normalize import _load_nvd_index, _load_osv_index, _normalize_record


class NormalizeTests(unittest.TestCase):
    def test_cve_1999_0428_extracts_cvss_v2_base_severity(self) -> None:
        nvd_index = _load_nvd_index()
        osv_index = _load_osv_index()

        record = _normalize_record(
            "CVE-1999-0428",
            nvd_index.get("CVE-1999-0428", []),
            osv_index.get("CVE-1999-0428", []),
        )

        self.assertEqual(record["cvss_score"], 7.5)
        self.assertEqual(record["cvss_severity"], "HIGH")

    def test_cve_2020_28500_keeps_only_lodash_in_affected_packages(self) -> None:
        nvd_index = _load_nvd_index()
        osv_index = _load_osv_index()

        record = _normalize_record(
            "CVE-2020-28500",
            nvd_index.get("CVE-2020-28500", []),
            osv_index.get("CVE-2020-28500", []),
        )

        self.assertEqual(len(record["affected_packages"]), 1)
        self.assertEqual(record["affected_packages"][0]["name"], "lodash")
        self.assertEqual(record["affected_packages"][0]["ecosystem"], "npm")
        self.assertEqual(record["affected_packages"][0]["version_ranges"], [{"fixed": "4.17.21"}])


if __name__ == "__main__":
    unittest.main()
