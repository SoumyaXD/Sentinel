from __future__ import annotations

import unittest

from eval.run_eval import _score_factual_accuracy, _score_trap_handled
from ingest.normalize import _nvd_version_range


class RunEvalTests(unittest.TestCase):
    def test_trap_handled_is_case_insensitive(self) -> None:
        self.assertTrue(_score_trap_handled("No matching CVE found for query: What is CVE-2099-12345?"))

    def test_trap_handled_accepts_relevant_phrase(self) -> None:
        self.assertTrue(_score_trap_handled("No relevant CVE found."))

    def test_factual_accuracy_accepts_numeric_score_variants(self) -> None:
        expected_facts = {"cvss_score": 10.0, "cvss_severity": "CRITICAL"}

        self.assertTrue(
            _score_factual_accuracy(
                "This vulnerability has CVSS 10/10 and is CRITICAL.",
                expected_facts,
            )
        )
        self.assertTrue(
            _score_factual_accuracy(
                "This vulnerability has CVSS 10.0 and is CRITICAL.",
                expected_facts,
            )
        )
        self.assertTrue(
            _score_factual_accuracy(
                "This vulnerability has CVSS 10 and is CRITICAL.",
                expected_facts,
            )
        )

    def test_citation_correct_should_allow_extra_grounded_cves(self) -> None:
        from eval.run_eval import _score_citation_correct

        self.assertTrue(
            _score_citation_correct(
                ["CVE-2021-23337", "CVE-2026-4800"],
                ["CVE-2021-23337"],
            )
        )
        self.assertFalse(
            _score_citation_correct(
                ["CVE-2026-4800"],
                ["CVE-2021-23337"],
            )
        )

    def test_nvd_inclusive_end_maps_to_last_affected(self) -> None:
        self.assertEqual(
            _nvd_version_range(
                {
                    "criteria": "cpe:2.3:a:axios:axios:*:*:*:*:*:node.js:*:*",
                    "vulnerable": True,
                    "versionEndIncluding": "0.18.0",
                }
            ),
            {"last_affected": "0.18.0"},
        )


if __name__ == "__main__":
    unittest.main()
