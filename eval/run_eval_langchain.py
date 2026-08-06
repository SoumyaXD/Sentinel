"""Stage B evaluation harness for the LangChain-based RAG pipeline."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from eval.run_eval import (
    _load_eval_set,
    _score_citation_correct,
    _score_factual_accuracy,
    _score_retrieved_correct_cve,
    _score_trap_handled,
)
from rag.chains import get_retriever
from rag.generation_chain import generate_answer
from rag.retriever import CVE_ID_RE, retrieve as stage_a_retrieve


EVAL_SET_PATH = "eval/eval_set.json"
RESULTS_DIR = Path("eval/results")
MAX_RETRIES = 2
RETRY_DELAY = 3  # seconds
ENTRY_DELAY = 1  # seconds between entries
BASELINE = {
    "retrieved_correct_cve": 94.4,
    "factual_accuracy": 94.4,
    "citation_correct": 94.4,
    "trap_handled": 100.0,
}


def _coerce_chunk(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return item

    page_content = getattr(item, "page_content", "")
    metadata = getattr(item, "metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    return {
        "text": page_content,
        "metadata": metadata,
    }


def _load_retrieved_chunks(question: str) -> tuple[str, list[dict[str, Any]]]:
    match = CVE_ID_RE.search(question)
    if match:
        documents = stage_a_retrieve(question)
        return ("rag.retriever.retrieve (exact-ID bypass)", [_coerce_chunk(document) for document in documents])

    retriever = get_retriever()
    documents = retriever.invoke(question)
    return ("rag.chains.get_retriever().invoke (semantic LangChain)", [_coerce_chunk(document) for document in documents])


def _save_results(results: list[dict[str, Any]], total_entries: int, filepath: str | None = None) -> str:
    """Save results to a JSON file (incremental or final)."""
    if filepath is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"run_langchain_{timestamp}.json"
        filepath = str(RESULTS_DIR / filename)

    output = {
        "generated_at": datetime.now().isoformat(),
        "eval_set_path": EVAL_SET_PATH,
        "total_entries": total_entries,
        "completed_entries": len(results),
        "results": results,
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, ensure_ascii=False)

    return filepath


def _run_single_eval(entry: dict[str, Any]) -> dict[str, Any]:
    question = entry["question"]
    entry_type = entry["type"]
    expected_cve_ids = entry.get("expected_cve_ids", [])
    expected_facts = entry.get("expected_facts", {})

    retrieval_path, retrieved_chunks = _load_retrieved_chunks(question)
    print(f"  Retrieval path: {retrieval_path} -> {len(retrieved_chunks)} chunks")

    result = None
    for attempt in range(MAX_RETRIES):
        try:
            result = generate_answer(question, retrieved_chunks)
            break
        except Exception:
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_DELAY * (2**attempt)
                print(f"  Rate limited (attempt {attempt + 1}/{MAX_RETRIES}), waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise

    answer = result.get("answer", "")
    cited_cve_ids = result.get("cited_cve_ids", [])

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
        "retrieval_path": retrieval_path,
        "retrieved_chunk_count": len(retrieved_chunks),
        "metrics": {
            "retrieved_correct_cve": retrieved_correct_cve,
            "factual_accuracy": factual_accuracy,
            "citation_correct": citation_correct,
            "trap_handled": trap_handled,
        },
    }


def _print_results_table(results: list[dict[str, Any]]) -> None:
    print("\n" + "=" * 100)
    print("PER-QUESTION RESULTS")
    print("=" * 100)

    for result in results:
        metrics = result["metrics"]
        id_ = result["id"]
        type_ = result["type"]

        ret_cve = "PASS" if metrics["retrieved_correct_cve"] else "FAIL"
        fact_acc_str = "PASS" if metrics["factual_accuracy"] else "FAIL"
        cit_corr = "PASS" if metrics["citation_correct"] else "FAIL"

        if metrics["trap_handled"] is not None:
            trap_hand = "PASS" if metrics["trap_handled"] else "FAIL"
        else:
            trap_hand = "N/A"

        print(f"\n[{id_}] Type: {type_}")
        print(f"  Question: {result['question']}")
        print(
            "  Metrics: "
            f"retrieved_correct_cve={ret_cve} | "
            f"factual_accuracy={fact_acc_str} | "
            f"citation_correct={cit_corr} | "
            f"trap_handled={trap_hand}"
        )
        print(
            f"  Retrieval: {result['retrieval_path']} -> {result['retrieved_chunk_count']} chunks"
        )

        if (
            not metrics["retrieved_correct_cve"]
            or metrics["citation_correct"] is False
            or metrics["trap_handled"] is False
        ):
            print(f"  Expected CVE IDs: {result['expected_cve_ids']}")
            print(f"  Cited CVE IDs: {result['cited_cve_ids']}")
            print(f"  Answer: {result['answer']}")


def _summarize(results: list[dict[str, Any]]) -> dict[str, float]:
    total = len(results)
    retrieved_correct = sum(1 for r in results if r["metrics"]["retrieved_correct_cve"])
    citation_correct = sum(1 for r in results if r["metrics"]["citation_correct"])
    factual_correct = sum(1 for r in results if r["metrics"]["factual_accuracy"])

    trap_results = [r for r in results if r["metrics"]["trap_handled"] is not None]
    if trap_results:
        trap_correct = sum(1 for r in trap_results if r["metrics"]["trap_handled"])
        trap_pct = (trap_correct / len(trap_results)) * 100
    else:
        trap_correct = 0
        trap_pct = 0.0

    retrieved_pct = (retrieved_correct / total) * 100 if total else 0.0
    citation_pct = (citation_correct / total) * 100 if total else 0.0
    factual_pct = (factual_correct / total) * 100 if total else 0.0

    print("\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    print(f"Total entries: {total}")
    print(f"Retrieved correct CVE: {retrieved_correct}/{total} ({retrieved_pct:.1f}%)")
    print(f"Factual accuracy: {factual_correct}/{total} ({factual_pct:.1f}%)")
    print(f"Citation correct: {citation_correct}/{total} ({citation_pct:.1f}%)")
    print(f"Trap handled: {trap_correct}/{len(trap_results)} ({trap_pct:.1f}%)")
    print()

    return {
        "retrieved_correct_cve": retrieved_pct,
        "factual_accuracy": factual_pct,
        "citation_correct": citation_pct,
        "trap_handled": trap_pct,
    }


def _print_side_by_side_summary(current: dict[str, float]) -> None:
    print("\n" + "=" * 100)
    print("B3 VS STAGE A BASELINE")
    print("=" * 100)
    print(f"{'Metric':<24}{'B3 LangChain':<18}{'Stage A baseline':<20}{'Delta'}")
    for metric in ("retrieved_correct_cve", "factual_accuracy", "citation_correct", "trap_handled"):
        current_value = current[metric]
        baseline_value = BASELINE[metric]
        delta = current_value - baseline_value
        print(
            f"{metric:<24}"
            f"{current_value:>7.1f}%{'':<10}"
            f"{baseline_value:>7.1f}%{'':<13}"
            f"{delta:+.1f}"
        )


def main() -> None:
    print("Loading evaluation set...")
    eval_set = _load_eval_set()
    entries = eval_set.get("entries", [])
    total_entries = len(entries)

    print(f"Running LangChain evaluation on {total_entries} entries...")
    results = []
    results_filepath = None

    for i, entry in enumerate(entries, 1):
        print(f"\n[{i}/{total_entries}] Processing {entry['id']}...")
        result = _run_single_eval(entry)
        results.append(result)

        results_filepath = _save_results(results, total_entries, results_filepath)
        print(f"  -> Progress saved ({len(results)}/{total_entries} complete)")

        if i < total_entries:
            time.sleep(ENTRY_DELAY)

    current_summary = _summarize(results)
    _print_results_table(results)
    _print_side_by_side_summary(current_summary)

    print(f"Final results saved to: {results_filepath}")


if __name__ == "__main__":
    main()
