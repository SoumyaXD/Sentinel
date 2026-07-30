from __future__ import annotations

import unittest
from unittest.mock import patch

from rag.retriever import retrieve


class RetrieverTests(unittest.TestCase):
    def test_exact_cve_id_lookup_returns_all_chunks(self) -> None:
        results = retrieve("What is CVE-2020-28500?")

        self.assertGreaterEqual(len(results), 1)
        self.assertTrue(all(result["metadata"]["cve_id"] == "CVE-2020-28500" for result in results))
        self.assertTrue(all(result["similarity"] is None for result in results))

    def test_missing_cve_id_returns_empty_list(self) -> None:
        results = retrieve("What is CVE-9999-99999?")

        self.assertEqual(results, [])

    def test_package_mention_boosts_matching_results(self) -> None:
        fake_results = [
            {
                "id": "CVE-1",
                "text": "django result",
                "metadata": {"affected_packages": [{"name": "django", "ecosystem": "pypi"}]},
                "distance": 0.8,
                "similarity": 0.2,
            },
            {
                "id": "CVE-2",
                "text": "lodash result",
                "metadata": {"affected_packages": [{"name": "lodash", "ecosystem": "npm"}]},
                "distance": 0.2,
                "similarity": 0.8,
            },
        ]

        with patch("rag.retriever._semantic_search", return_value=fake_results):
            results = retrieve("lodash regex denial of service", k=1)

        self.assertEqual(results[0]["metadata"]["affected_packages"][0]["name"], "lodash")


if __name__ == "__main__":
    unittest.main()
