from __future__ import annotations

import unittest

from rag.chunk import chunk_cve_record


class ChunkCveRecordTests(unittest.TestCase):
    def test_nvd_only_record_stays_single_chunk(self) -> None:
        record = {
            "cve_id": "CVE-TEST-0001",
            "description": "Example vulnerability in widget parser.",
            "sources": ["nvd"],
            "cvss_score": 7.5,
            "cvss_severity": "HIGH",
            "affected_packages": [
                {
                    "name": "widget",
                    "ecosystem": "npm",
                    "version_ranges": [{"fixed": "1.2.3"}],
                }
            ],
        }

        chunks = chunk_cve_record(record)

        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0]["metadata"]["chunk_type"], "full")
        self.assertIn("CVE-TEST-0001 (CVSS 7.5, HIGH):", chunks[0]["text"])
        self.assertIn("Affects widget (npm) versions before 1.2.3.", chunks[0]["text"])

    def test_rich_osv_record_splits_into_section_chunks(self) -> None:
        record = {
            "cve_id": "CVE-TEST-0002",
            "description": (
                "Summary of the issue.\n\n"
                "## Impact\n"
                "The bug causes denial of service.\n\n"
                "## Fix\n"
                "Upgrade to version 2.0.0.\n"
            ),
            "sources": ["nvd", "osv"],
            "cvss_score": 9.1,
            "cvss_severity": "CRITICAL",
            "affected_packages": [
                {
                    "name": "package-two",
                    "ecosystem": "PyPI",
                    "version_ranges": [{"introduced": "1.0.0", "fixed": "2.0.0"}],
                }
            ],
        }

        chunks = chunk_cve_record(record)

        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(chunk["metadata"]["chunk_type"].startswith("section:") for chunk in chunks))
        self.assertTrue(all("CVE-TEST-0002 (CVSS 9.1, CRITICAL):" in chunk["text"] for chunk in chunks))


if __name__ == "__main__":
    unittest.main()
