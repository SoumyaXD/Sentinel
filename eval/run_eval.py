"""Evaluation harness for scoring the RAG pipeline against a hand-verified eval set."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime
from typing import Any

from rag.generate import generate_answer
from rag.retriever import retrieve


EVAL_SET_PATH = "eval/eval_set.json"
RESULTS_DIR = "eval/results"
MAX_RETRIES = 2
RETRY_DELAY = 3  # seconds
ENTRY_DELAY = 1  # seconds between entries
CVSS_NUMBER_RE = re.compile(r"(?<!\d)(\d+(?:\.\d+)?)(?:\s*/\s*10)?(?!\d)")


def _load_eval_set() -> dict[str, Any]:
    with open(EVAL_SET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _score_retrieved_correct_cve(
    retrieved_chunks: list[dict[str, Any]], expected_cve_ids: list[str]
) -> bool:
    """Check if retrieval's top results contain the expected CVE IDs."""
    if not expected_cve_ids:
        return True
    
    retrieved_cve_ids = set()
    for chunk in retrieved_chunks:
        metadata = chunk.get("metadata", {})
        if isinstance(metadata, dict):
            cve_id = metadata.get("cve_id")
            if cve_id:
                retrieved_cve_ids.add(cve_id.upper())
    
    expected_set = {cve.upper() for cve in expected_cve_ids}
    return expected_set.issubset(retrieved_cve_ids)


def _score_factual_accuracy(
    answer: str, expected_facts: dict[str, Any]
) -> bool:
    """
    Check if the generated answer's stated facts match expected_facts.
    Returns True if accurate, False if inaccurate.
    """
    # Trap question case: expected_facts is None/empty
    if not expected_facts:
        return True
    
    cvss_score = expected_facts.get("cvss_score")
    cvss_severity = expected_facts.get("cvss_severity")
    
    # Missing CVSS case: check that answer does NOT fabricate a CVSS score
    if cvss_score is None and cvss_severity is None:
        # Check if answer contains "CVSS" followed by a number (hallucinated score)
        import re
        cvss_pattern = re.compile(r"CVSS.*?\d", re.IGNORECASE)
        if cvss_pattern.search(answer):
            return False
        return True
    
    # CVSS data expected: check that answer contains both score and severity
    answer_lower = answer.lower()
    
    # Check for CVSS score with numeric-tolerant matching.
    try:
        expected_score = float(cvss_score)
    except (TypeError, ValueError):
        return False

    score_found = False
    for match in CVSS_NUMBER_RE.finditer(answer):
        try:
            if float(match.group(1)) == expected_score:
                score_found = True
                break
        except ValueError:
            continue

    if not score_found:
        return False

    # Check for CVSS severity (case-insensitive)
    if cvss_severity and cvss_severity.lower() not in answer_lower:
        return False
    
    return True


def _score_citation_correct(
    cited_cve_ids: list[str], expected_cve_ids: list[str]
) -> bool:
    """Check if every expected CVE ID was cited, allowing extra grounded citations."""
    cited_set = {cve.upper() for cve in cited_cve_ids}
    expected_set = {cve.upper() for cve in expected_cve_ids}
    return expected_set.issubset(cited_set)


def _score_trap_handled(answer: str) -> bool:
    """Check if the pipeline correctly returned 'no matching CVE found' for trap questions."""
    answer_lower = answer.lower()
    return any(
        phrase in answer_lower
        for phrase in ("no matching cve found", "no relevant cve found")
    )


def _run_single_eval(entry: dict[str, Any]) -> dict[str, Any]:
    """Run the pipeline for a single eval entry and score it."""
    question = entry["question"]
    entry_type = entry["type"]
    expected_cve_ids = entry.get("expected_cve_ids", [])
    expected_facts = entry.get("expected_facts", {})
    
    retrieved_chunks = retrieve(question)
    
    # Retry generate_answer with exponential backoff for rate limiting
    result = None
    for attempt in range(MAX_RETRIES):
        try:
            result = generate_answer(question, retrieved_chunks)
            break
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_DELAY * (2 ** attempt)
                print(f"  Rate limited (attempt {attempt + 1}/{MAX_RETRIES}), waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise
    
    answer = result.get("answer", "")
    cited_cve_ids = result.get("cited_cve_ids", [])
    
    # Score metrics
    retrieved_correct_cve = _score_retrieved_correct_cve(retrieved_chunks, expected_cve_ids)
    factual_accuracy = _score_factual_accuracy(answer, expected_facts)
    citation_correct = _score_citation_correct(cited_cve_ids, expected_cve_ids)
    
    trap_handled = None
    if entry_type == "trap_question":
        trap_handled = _score_trap_handled(answer)
    
    return {
        "id": entry["id"],
        "type": entry_type,
        "question": question,
        "expected_cve_ids": expected_cve_ids,
        "cited_cve_ids": cited_cve_ids,
        "answer": answer,
        "metrics": {
            "retrieved_correct_cve": retrieved_correct_cve,
            "factual_accuracy": factual_accuracy,
            "citation_correct": citation_correct,
            "trap_handled": trap_handled,
        },
    }


def _print_results_table(results: list[dict[str, Any]]) -> None:
    """Print a per-question result table."""
    print("\n" + "=" * 100)
    print("PER-QUESTION RESULTS")
    print("=" * 100)
    
    for result in results:
        metrics = result["metrics"]
        id_ = result["id"]
        type_ = result["type"]
        
        # Format metric status
        ret_cve = "PASS" if metrics["retrieved_correct_cve"] else "FAIL"
        fact_acc_str = "PASS" if metrics["factual_accuracy"] else "FAIL"
        cit_corr = "PASS" if metrics["citation_correct"] else "FAIL"
        
        if metrics["trap_handled"] is not None:
            trap_hand = "PASS" if metrics["trap_handled"] else "FAIL"
        else:
            trap_hand = "N/A"
        
        print(f"\n[{id_}] Type: {type_}")
        print(f"  Question: {result['question']}")
        print(f"  Metrics: retrieved_correct_cve={ret_cve} | factual_accuracy={fact_acc_str} | citation_correct={cit_corr} | trap_handled={trap_hand}")
        
        # Print full details for failing entries
        if not metrics["retrieved_correct_cve"] or metrics["citation_correct"] is False or metrics["trap_handled"] is False:
            print(f"  Expected CVE IDs: {result['expected_cve_ids']}")
            print(f"  Cited CVE IDs: {result['cited_cve_ids']}")
            print(f"  Answer: {result['answer']}")


def _print_summary(results: list[dict[str, Any]]) -> None:
    """Print final summary statistics."""
    print("\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    
    total = len(results)
    
    # Count passes for each metric
    retrieved_correct = sum(1 for r in results if r["metrics"]["retrieved_correct_cve"])
    citation_correct = sum(1 for r in results if r["metrics"]["citation_correct"])
    factual_correct = sum(1 for r in results if r["metrics"]["factual_accuracy"])
    
    # Trap handling (only for trap questions)
    trap_results = [r for r in results if r["metrics"]["trap_handled"] is not None]
    if trap_results:
        trap_correct = sum(1 for r in trap_results if r["metrics"]["trap_handled"])
        trap_pct = (trap_correct / len(trap_results)) * 100
    else:
        trap_pct = 0.0
    
    retrieved_pct = (retrieved_correct / total) * 100
    citation_pct = (citation_correct / total) * 100
    factual_pct = (factual_correct / total) * 100
    
    print(f"Total entries: {total}")
    print(f"Retrieved correct CVE: {retrieved_correct}/{total} ({retrieved_pct:.1f}%)")
    print(f"Factual accuracy: {factual_correct}/{total} ({factual_pct:.1f}%)")
    print(f"Citation correct: {citation_correct}/{total} ({citation_pct:.1f}%)")
    print(f"Trap handled: {trap_correct}/{len(trap_results)} ({trap_pct:.1f}%)")
    print()


def _save_results(results: list[dict[str, Any]], total_entries: int, filepath: str | None = None) -> str:
    """Save results to a JSON file (incremental or final)."""
    if filepath is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"run_{timestamp}.json"
        filepath = os.path.join(RESULTS_DIR, filename)
    
    output = {
        "generated_at": datetime.now().isoformat(),
        "eval_set_path": EVAL_SET_PATH,
        "total_entries": total_entries,
        "completed_entries": len(results),
        "results": results,
    }
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    return filepath


def main() -> None:
    print("Loading evaluation set...")
    eval_set = _load_eval_set()
    entries = eval_set.get("entries", [])
    total_entries = len(entries)
    
    print(f"Running evaluation on {total_entries} entries...")
    results = []
    results_filepath = None
    
    for i, entry in enumerate(entries, 1):
        print(f"\n[{i}/{total_entries}] Processing {entry['id']}...")
        result = _run_single_eval(entry)
        results.append(result)
        
        # Save results incrementally after each entry
        results_filepath = _save_results(results, total_entries, results_filepath)
        print(f"  -> Progress saved ({len(results)}/{total_entries} complete)")
        
        # Add delay between entries to avoid rate limiting
        if i < total_entries:
            time.sleep(ENTRY_DELAY)
    
    _print_results_table(results)
    _print_summary(results)
    
    print(f"Final results saved to: {results_filepath}")


if __name__ == "__main__":
    main()
