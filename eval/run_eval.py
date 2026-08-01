"""Evaluation harness for scoring the RAG pipeline against a hand-verified eval set."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Any

from rag.generate import generate_answer
from rag.retriever import retrieve


EVAL_SET_PATH = "eval/eval_set.json"
RESULTS_DIR = "eval/results"
MAX_RETRIES = 10
RETRY_DELAY = 3  # seconds
ENTRY_DELAY = 1  # seconds between entries


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
) -> bool | str:
    """
    Check if the generated answer's stated facts match expected_facts.
    Returns True if accurate, False if inaccurate, or "skipped" if expected_facts
    is not populated for manual verification.
    """
    if not expected_facts or expected_facts.get("status") == "NEEDS MANUAL VERIFICATION":
        return "skipped"
    
    # TODO: Implement actual fact comparison when expected_facts is populated
    # For now, since eval_set.json has placeholder expected_facts, we skip this check
    return "skipped"


def _score_citation_correct(
    cited_cve_ids: list[str], expected_cve_ids: list[str]
) -> bool:
    """Check if cited_cve_ids match expected_cve_ids exactly."""
    cited_set = {cve.upper() for cve in cited_cve_ids}
    expected_set = {cve.upper() for cve in expected_cve_ids}
    return cited_set == expected_set


def _score_trap_handled(answer: str) -> bool:
    """Check if the pipeline correctly returned 'no matching CVE found' for trap questions."""
    return "no matching CVE found" in answer.lower()


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
        fact_acc = metrics["factual_accuracy"]
        if fact_acc == "skipped":
            fact_acc_str = "SKIP"
        else:
            fact_acc_str = "PASS" if fact_acc else "FAIL"
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
    
    # Factual accuracy (excluding skipped)
    factual_results = [r for r in results if r["metrics"]["factual_accuracy"] != "skipped"]
    if factual_results:
        factual_correct = sum(1 for r in factual_results if r["metrics"]["factual_accuracy"])
        factual_pct = (factual_correct / len(factual_results)) * 100
    else:
        factual_pct = 0.0
    
    # Trap handling (only for trap questions)
    trap_results = [r for r in results if r["metrics"]["trap_handled"] is not None]
    if trap_results:
        trap_correct = sum(1 for r in trap_results if r["metrics"]["trap_handled"])
        trap_pct = (trap_correct / len(trap_results)) * 100
    else:
        trap_pct = 0.0
    
    retrieved_pct = (retrieved_correct / total) * 100
    citation_pct = (citation_correct / total) * 100
    
    print(f"Total entries: {total}")
    print(f"Retrieved correct CVE: {retrieved_correct}/{total} ({retrieved_pct:.1f}%)")
    print(f"Factual accuracy: {len(factual_results)} scored, {factual_pct:.1f}% (others skipped due to unverified expected_facts)")
    print(f"Citation correct: {citation_correct}/{total} ({citation_pct:.1f}%)")
    print(f"Trap handled: {trap_correct}/{len(trap_results)} ({trap_pct:.1f}%)")
    print()


def _save_results(results: list[dict[str, Any]]) -> str:
    """Save full results to a timestamped JSON file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"run_{timestamp}.json"
    filepath = os.path.join(RESULTS_DIR, filename)
    
    output = {
        "generated_at": datetime.now().isoformat(),
        "eval_set_path": EVAL_SET_PATH,
        "total_entries": len(results),
        "results": results,
    }
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    return filepath


def main() -> None:
    print("Loading evaluation set...")
    eval_set = _load_eval_set()
    entries = eval_set.get("entries", [])
    
    print(f"Running evaluation on {len(entries)} entries...")
    results = []
    
    for i, entry in enumerate(entries, 1):
        print(f"\n[{i}/{len(entries)}] Processing {entry['id']}...")
        result = _run_single_eval(entry)
        results.append(result)
        
        # Add delay between entries to avoid rate limiting
        if i < len(entries):
            time.sleep(ENTRY_DELAY)
    
    _print_results_table(results)
    _print_summary(results)
    
    filepath = _save_results(results)
    print(f"Full results saved to: {filepath}")


if __name__ == "__main__":
    main()
