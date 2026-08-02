from __future__ import annotations

import unittest
from unittest.mock import patch

from rag.generate import generate_answer, _format_chunk_context


class GenerateAnswerTests(unittest.TestCase):
    def test_empty_retrieval_returns_deterministic_no_match_answer(self) -> None:
        with patch("rag.generate._call_llm") as mock_call_llm:
            result = generate_answer("What is CVE-9999-99999?", [])

        mock_call_llm.assert_not_called()
        self.assertEqual(result["cited_cve_ids"], [])
        self.assertIn("No matching CVE found", result["answer"])

    def test_response_citations_are_extracted_from_answer_text(self) -> None:
        retrieved_chunks = [
            {
                "text": "CVE-2020-28500 affects lodash.",
                "metadata": {
                    "cve_id": "CVE-2020-28500",
                    "chunk_type": "full",
                    "cvss_score": 7.5,
                    "cvss_severity": "HIGH",
                    "affected_packages": [],
                },
            }
        ]

        with patch(
            "rag.generate._call_llm",
            return_value="CVE-2020-28500 allows a denial of service [CVE-2020-28500].",
        ):
            result = generate_answer("What is CVE-2020-28500?", retrieved_chunks)

        self.assertEqual(result["cited_cve_ids"], ["CVE-2020-28500"])
        self.assertIn("[CVE-2020-28500]", result["answer"])

    def test_only_bracket_citations_are_counted(self) -> None:
        retrieved_chunks = [
            {
                "text": "CVE-2020-28500 affects lodash.",
                "metadata": {
                    "cve_id": "CVE-2020-28500",
                    "chunk_type": "full",
                    "cvss_score": 7.5,
                    "cvss_severity": "HIGH",
                    "affected_packages": [],
                },
            }
        ]

        with patch(
            "rag.generate._call_llm",
            return_value=(
                "CVE-2020-28500 is relevant in prose, but only [CVE-2020-28500] should count. "
                "CVE-1999-0001 is not relevant."
            ),
        ):
            result = generate_answer("What is CVE-2020-28500?", retrieved_chunks)

        self.assertEqual(result["cited_cve_ids"], ["CVE-2020-28500"])

    def test_citations_not_present_in_context_are_filtered(self) -> None:
        retrieved_chunks = [
            {
                "text": "CVE-2020-28500 affects lodash.",
                "metadata": {
                    "cve_id": "CVE-2020-28500",
                    "chunk_type": "full",
                    "cvss_score": 7.5,
                    "cvss_severity": "HIGH",
                    "affected_packages": [],
                },
            }
        ]

        with patch(
            "rag.generate._call_llm",
            return_value=(
                "The grounded answer cites [CVE-2020-28500] and an out-of-context citation [CVE-2026-4800]."
            ),
        ):
            result = generate_answer("What is CVE-2020-28500?", retrieved_chunks)

        self.assertEqual(result["cited_cve_ids"], ["CVE-2020-28500"])

    def test_missing_cvss_score_is_omitted_from_context(self) -> None:
        chunk = {
            "text": "CVE-2008-2302 affects a library described in the record.",
            "metadata": {
                "cve_id": "CVE-2008-2302",
                "chunk_type": "full",
                "cvss_score": None,
                "cvss_severity": None,
                "affected_packages": [{"name": "example", "ecosystem": "pypi"}],
            },
        }

        context = _format_chunk_context(chunk, 1)

        self.assertIn("CVE ID: CVE-2008-2302", context)
        self.assertNotIn("CVSS:", context)
        self.assertIn("Affected package: example (pypi)", context)


if __name__ == "__main__":
    unittest.main()
