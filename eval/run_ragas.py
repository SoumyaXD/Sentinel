"""RAGAS evaluation harness for the Stage B LangChain RAG pipeline."""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from statistics import fmean
from typing import Any, TypeVar

try:
    from instructor.v2.core.errors import IncompleteOutputException
except ImportError:  # pragma: no cover - instructor version dependent
    IncompleteOutputException = None

from eval.run_eval import _load_eval_set
from rag.chains import get_retriever
from rag.generation_chain import generate_answer
from rag.retriever import CVE_ID_RE, retrieve as stage_a_retrieve


EVAL_SET_PATH = "eval/eval_set.json"
RESULTS_DIR = Path("eval/results")
MAX_RETRIES = 2
RETRY_DELAY = 3  # seconds
ENTRY_DELAY = 1  # seconds between entries
DEFAULT_GENERATION_CALL_COST = 0.002
DEFAULT_JUDGE_CALL_COST = 0.002
T = TypeVar("T")


def _document_to_chunk(document: Any) -> dict[str, Any]:
    """Coerce a LangChain document into the chunk shape expected by generation."""

    if isinstance(document, dict):
        text = document.get("text", document.get("page_content", ""))
        metadata = document.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        return {
            "text": text,
            "metadata": metadata,
        }

    page_content = getattr(document, "page_content", "")
    metadata = getattr(document, "metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    return {
        "text": page_content,
        "metadata": metadata,
    }


def _document_to_text(document: Any) -> str:
    """Extract plain text from a LangChain document or chunk-like mapping."""

    if isinstance(document, dict):
        text = document.get("text", document.get("page_content", ""))
        return str(text).strip()

    return str(getattr(document, "page_content", "")).strip()


def _load_eval_entries() -> list[dict[str, Any]]:
    eval_set = _load_eval_set()
    entries = eval_set.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("Expected eval/eval_set.json to contain an 'entries' list")
    return [entry for entry in entries if isinstance(entry, dict)]


def _count_scored_entries(entries: list[dict[str, Any]]) -> int:
    return sum(1 for entry in entries if entry.get("type") != "trap_question")


def _is_genuine_refusal(answer: str) -> bool:
    """Detect if an answer is a genuine refusal (pipeline declined to answer a real question)."""
    refusal_patterns = [
        "No matching CVE found",
        "No relevant CVE found",
        "cannot provide an answer",
        "does not mention any CVEs",
        "no CVEs that specifically affect",
        "no information available regarding",
    ]
    answer_lower = answer.lower()
    return any(pattern.lower() in answer_lower for pattern in refusal_patterns)


def _format_currency(value: float) -> str:
    return f"${value:,.4f}"


def _estimate_run_cost(total_entries: int, scored_entries: int) -> tuple[int, int, int, float]:
    generation_calls = total_entries
    judge_calls = scored_entries * 2
    embedding_calls = scored_entries
    generation_cost = generation_calls * DEFAULT_GENERATION_CALL_COST
    judge_cost = judge_calls * DEFAULT_JUDGE_CALL_COST
    total_cost = generation_cost + judge_cost
    return generation_calls, judge_calls, embedding_calls, total_cost


def _print_cost_estimate(total_entries: int, scored_entries: int) -> None:
    generation_calls, judge_calls, embedding_calls, total_cost = _estimate_run_cost(
        total_entries, scored_entries
    )
    print("\n" + "=" * 100)
    print("COST ESTIMATE")
    print("=" * 100)
    print(f"Entries to process: {total_entries}")
    print(f"Entries to RAGAS-score: {scored_entries} (trap questions excluded)")
    print(f"Estimated generation calls: {generation_calls}")
    print(f"Estimated RAGAS judge calls: {judge_calls} (Faithfulness + AnswerRelevancy)")
    print(f"Estimated AnswerRelevancy embedding calls: {embedding_calls} (not priced in rough total)")
    print(
        "Assumed rough per-call costs: "
        f"generation={_format_currency(DEFAULT_GENERATION_CALL_COST)}, "
        f"judge={_format_currency(DEFAULT_JUDGE_CALL_COST)}"
    )
    print(f"Estimated total API cost (rough, generation + judge only): {_format_currency(total_cost)}")
    print(
        "Note: ContextPrecision and ContextRecall are intentionally skipped for now "
        "because eval/eval_set.json does not include labeled reference answers."
    )
    print()


def _confirm_run() -> bool:
    response = input("Proceed with the full RAGAS evaluation run? [y/N] ").strip().lower()
    return response in {"y", "yes"}


def _save_results(results: list[dict[str, Any]], total_entries: int, filepath: str | None = None) -> str:
    """Save results to a JSON file, keeping the write path stable during the run."""

    if filepath is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = str(RESULTS_DIR / f"run_ragas_{timestamp}.json")

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


def _score_value(result: Any) -> float:
    """Extract the numeric score from a RAGAS MetricResult."""

    value = getattr(result, "value", result)
    return float(value)


def _build_ragas_metrics() -> tuple[Any, Any]:
    """Construct the current RAGAS v0.4 collection metrics."""

    try:
        from openai import AsyncOpenAI
        from ragas.embeddings.base import embedding_factory
        from ragas.llms import llm_factory
        from ragas.metrics.collections import AnswerRelevancy, Faithfulness
    except ModuleNotFoundError as exc:  # pragma: no cover - environment issue
        raise RuntimeError(
            f"Missing module: {exc.name}"
        ) from exc

    client_kwargs: dict[str, Any] = {
        "timeout": float(os.getenv("RAGAS_OPENAI_TIMEOUT", "60")),
        "max_retries": int(os.getenv("RAGAS_OPENAI_MAX_RETRIES", "5")),
        "max_completion_tokens": int(os.getenv("RAGAS_OPENAI_MAX_TOKENS", "2048")),
    }
    base_url = os.getenv("RAGAS_OPENAI_BASE_URL", os.getenv("OPENAI_BASE_URL", "")).strip()
    if base_url:
        client_kwargs["base_url"] = base_url

    client = AsyncOpenAI(**client_kwargs)

    judge_model = os.getenv("RAGAS_JUDGE_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
    embedding_model = (
        os.getenv("RAGAS_EMBEDDING_MODEL", "text-embedding-3-small").strip()
        or "text-embedding-3-small"
    )

    judge = llm_factory(judge_model, client=client)
    embeddings = embedding_factory("openai", model=embedding_model, client=client)
    faithfulness = Faithfulness(llm=judge)
    answer_relevancy = AnswerRelevancy(llm=judge, embeddings=embeddings)
    return faithfulness, answer_relevancy


def _load_retrieved_contexts(
    question: str,
) -> tuple[str, list[dict[str, Any]], list[str]]:
    match = CVE_ID_RE.search(question)

    if match:
        documents = stage_a_retrieve(question)
        retrieval_path = "rag.retriever.retrieve (exact-ID bypass)"
    else:
        retriever = get_retriever()
        documents = retriever.invoke(question)
        retrieval_path = "rag.chains.get_retriever().invoke (semantic LangChain)"

    chunks = [_document_to_chunk(document) for document in documents]

    contexts: list[str] = []
    for document in documents:
        text = _document_to_text(document)
        if text:
            contexts.append(text)

    return (
        retrieval_path,
        chunks,
        contexts,
    )


def _call_generation_with_retry(question: str, retrieved_chunks: list[dict[str, Any]]) -> dict[str, Any]:
    """Run the grounded generation chain with simple retry handling."""

    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            return generate_answer(question, retrieved_chunks)
        except Exception as exc:  # pragma: no cover - provider/runtime dependent
            last_error = exc
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_DELAY * (2**attempt)
                print(
                    f"  Generation call failed (attempt {attempt + 1}/{MAX_RETRIES}), "
                    f"waiting {wait_time}s..."
                )
                time.sleep(wait_time)
            else:
                raise

    raise RuntimeError("Generation failed unexpectedly") from last_error


async def _call_metric_with_retry(
    label: str,
    scorer: Any,
    *,
    payload: dict[str, Any],
) -> Any:
    """Run a RAGAS metric with simple retry handling."""

    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            return await scorer.ascore(**payload)
        except Exception as exc:  # pragma: no cover - provider/runtime dependent
            last_error = exc
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_DELAY * (2**attempt)
                print(
                    f"  {label} failed (attempt {attempt + 1}/{MAX_RETRIES}), "
                    f"waiting {wait_time}s..."
                )
                await asyncio.sleep(wait_time)
            else:
                # If it's an IncompleteOutputException, log it and return None
                # so the caller can handle it gracefully without crashing the entire run
                if IncompleteOutputException is not None and isinstance(exc, IncompleteOutputException):
                    print(f"  {label} failed after {MAX_RETRIES} attempts: {type(exc).__name__} - {exc}")
                    return None
                raise

    raise RuntimeError(f"{label} failed unexpectedly") from last_error


async def _evaluate_entry(
    entry: dict[str, Any],
    faithfulness: Any,
    answer_relevancy: Any,
) -> dict[str, Any]:
    question = entry["question"]
    entry_type = entry["type"]
    retrieval_path, retrieved_chunks, retrieved_contexts = _load_retrieved_contexts(question)
    print(f"  Retrieval path: {retrieval_path} -> {len(retrieved_contexts)} contexts")

    result = _call_generation_with_retry(question, retrieved_chunks)
    answer = result.get("answer", "")
    cited_cve_ids = result.get("cited_cve_ids", [])

    ragas_result: dict[str, Any]
    if entry_type == "trap_question":
        reason = (
            "Trap questions are excluded from RAGAS scoring because a deterministic "
            "no-match response is not a meaningful faithfulness/relevancy target."
        )
        ragas_result = {
            "status": "excluded",
            "reason": reason,
            "faithfulness": None,
            "answer_relevancy": None,
        }
    elif not retrieved_contexts:
        reason = "No retrieved context was returned, so RAGAS faithfulness/relevancy would not be meaningful."
        ragas_result = {
            "status": "excluded",
            "reason": reason,
            "faithfulness": None,
            "answer_relevancy": None,
        }
    elif _is_genuine_refusal(answer):
        reason = (
            "Genuine refusal (pipeline declined to answer a real question). "
            "RAGAS faithfulness/relevancy scoring is not meaningful for refusals "
            "since there are no claims to check for support."
        )
        ragas_result = {
            "status": "excluded_refusal",
            "reason": reason,
            "faithfulness": None,
            "answer_relevancy": None,
        }
    else:
        faithfulness_result = await _call_metric_with_retry(
            "Faithfulness",
            faithfulness,
            payload={
                "user_input": question,
                "response": answer,
                "retrieved_contexts": retrieved_contexts,
            },
        )
        answer_relevancy_result = await _call_metric_with_retry(
            "AnswerRelevancy",
            answer_relevancy,
            payload={
                "user_input": question,
                "response": answer,
            },
        )

        # Handle judge failures gracefully
        if faithfulness_result is None or answer_relevancy_result is None:
            failed_metrics = []
            if faithfulness_result is None:
                failed_metrics.append("Faithfulness")
            if answer_relevancy_result is None:
                failed_metrics.append("AnswerRelevancy")
            reason = (
                f"RAGAS judge call failed for {', '.join(failed_metrics)} after {MAX_RETRIES} retries. "
                "This entry could not be scored due to a judge error (e.g., token limit exceeded)."
            )
            ragas_result = {
                "status": "judge_error",
                "reason": reason,
                "faithfulness": _score_value(faithfulness_result) if faithfulness_result is not None else None,
                "answer_relevancy": _score_value(answer_relevancy_result) if answer_relevancy_result is not None else None,
            }
        else:
            ragas_result = {
                "status": "scored",
                "reason": None,
                "faithfulness": _score_value(faithfulness_result),
                "answer_relevancy": _score_value(answer_relevancy_result),
            }

    return {
        "id": entry["id"],
        "type": entry_type,
        "question": question,
        "expected_cve_ids": entry.get("expected_cve_ids", []),
        "cited_cve_ids": cited_cve_ids,
        "answer": answer,
        "retrieval_path": retrieval_path,
        "retrieved_contexts": retrieved_contexts,
        "ragas": ragas_result,
        "notes": entry.get("notes"),
    }


def _print_results_table(results: list[dict[str, Any]]) -> None:
    print("\n" + "=" * 100)
    print("PER-QUESTION RESULTS")
    print("=" * 100)

    for result in results:
        ragas = result["ragas"]
        print(f"\n[{result['id']}] Type: {result['type']}")
        print(f"  Question: {result['question']}")
        print(f"  Retrieval: {result['retrieval_path']} -> {len(result['retrieved_contexts'])} contexts")
        if ragas["status"] == "excluded":
            print(f"  RAGAS: EXCLUDED | {ragas['reason']}")
        else:
            print(
                "  RAGAS: "
                f"faithfulness={ragas['faithfulness']:.3f} | "
                f"answer_relevancy={ragas['answer_relevancy']:.3f}"
            )

        if ragas["status"] != "scored":
            print(f"  Answer: {result['answer']}")


def _summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    scored_results = [result for result in results if result["ragas"]["status"] == "scored"]
    excluded_results = [result for result in results if result["ragas"]["status"] == "excluded"]
    excluded_refusal_results = [result for result in results if result["ragas"]["status"] == "excluded_refusal"]
    judge_error_results = [result for result in results if result["ragas"]["status"] == "judge_error"]

    faithfulness_scores = [result["ragas"]["faithfulness"] for result in scored_results if result["ragas"]["faithfulness"] is not None]
    answer_relevancy_scores = [result["ragas"]["answer_relevancy"] for result in scored_results if result["ragas"]["answer_relevancy"] is not None]

    faithfulness_mean = fmean(faithfulness_scores) if faithfulness_scores else 0.0
    answer_relevancy_mean = fmean(answer_relevancy_scores) if answer_relevancy_scores else 0.0

    print("\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    print(f"Total entries: {len(results)}")
    print(f"RAGAS-scored entries: {len(scored_results)}")
    print(f"RAGAS-excluded entries (trap questions): {len(excluded_results)}")
    print(f"RAGAS-excluded entries (genuine refusals): {len(excluded_refusal_results)}")
    print(f"RAGAS-judge-error entries: {len(judge_error_results)}")
    print(f"Mean faithfulness: {faithfulness_mean:.3f}")
    print(f"Mean answer relevancy: {answer_relevancy_mean:.3f}")
    if excluded_results:
        print("Excluded trap questions:")
        for result in excluded_results:
            print(f"  - {result['id']}: {result['ragas']['reason']}")
    if excluded_refusal_results:
        print("Excluded genuine refusals:")
        for result in excluded_refusal_results:
            print(f"  - {result['id']}: {result['ragas']['reason']}")
    if judge_error_results:
        print("Judge error entries:")
        for result in judge_error_results:
            print(f"  - {result['id']}: {result['ragas']['reason']}")
    print()

    return {
        "scored_entries": len(scored_results),
        "excluded_trap_entries": len(excluded_results),
        "excluded_refusal_entries": len(excluded_refusal_results),
        "judge_error_entries": len(judge_error_results),
        "mean_faithfulness": faithfulness_mean,
        "mean_answer_relevancy": answer_relevancy_mean,
    }


async def main() -> None:
    print("Loading evaluation set...")
    entries = _load_eval_entries()
    total_entries = len(entries)
    scored_entries = _count_scored_entries(entries)

    _print_cost_estimate(total_entries, scored_entries)
    if not _confirm_run():
        print("Aborted before evaluation started.")
        return

    faithfulness, answer_relevancy = _build_ragas_metrics()

    print(f"Running RAGAS evaluation on {total_entries} entries...")
    results: list[dict[str, Any]] = []
    results_filepath: str | None = None

    for index, entry in enumerate(entries, start=1):
        print(f"\n[{index}/{total_entries}] Processing {entry['id']}...")
        result = await _evaluate_entry(entry, faithfulness, answer_relevancy)
        results.append(result)

        results_filepath = _save_results(results, total_entries, results_filepath)
        print(f"  -> Progress saved ({len(results)}/{total_entries} complete)")

        if index < total_entries:
            await asyncio.sleep(ENTRY_DELAY)

    _print_results_table(results)
    _summarize(results)

    print(f"Final results saved to: {results_filepath}")


if __name__ == "__main__":
    asyncio.run(main())
