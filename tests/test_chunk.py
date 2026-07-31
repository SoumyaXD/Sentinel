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

    def test_code_fence_stays_with_reproduction_section(self) -> None:
        record = {
            "cve_id": "CVE-TEST-0003",
            "description": (
                "Intro paragraph.\n\n"
                "Steps to reproduce:\n"
                "```js\n"
                "console.log('hello');\n"
                "```\n"
            ),
            "sources": ["osv"],
            "cvss_score": 5.3,
            "cvss_severity": "MEDIUM",
            "affected_packages": [
                {
                    "name": "lodash",
                    "ecosystem": "npm",
                    "version_ranges": [{"fixed": "4.17.21"}],
                }
            ],
        }

        chunks = chunk_cve_record(record)

        self.assertEqual(len(chunks), 2)
        self.assertIn("steps to reproduce.", chunks[1]["text"])
        self.assertIn("```js", chunks[1]["text"])
        self.assertIn("console.log('hello');", chunks[1]["text"])
        self.assertIn("```", chunks[1]["text"])

    def test_missing_cvss_omitted_from_chunk_text(self) -> None:
        record = {
            "cve_id": "CVE-TEST-0004",
            "description": "Example vulnerability with no severity score data.",
            "sources": ["osv"],
            "cvss_score": None,
            "cvss_severity": None,
            "affected_packages": [
                {
                    "name": "example",
                    "ecosystem": "PyPI",
                    "version_ranges": [{"fixed": "1.0.0"}],
                }
            ],
        }

        chunks = chunk_cve_record(record)

        self.assertEqual(len(chunks), 1)
        self.assertNotIn("CVSS", chunks[0]["text"])
        self.assertIn("CVE-TEST-0004:", chunks[0]["text"])


if __name__ == "__main__":
    unittest.main()
