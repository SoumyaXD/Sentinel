"""One-time script to generate demo_cache.json for the 18 eval questions."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.schemas import AskRequest
from rag.chains import get_retriever
from rag.generation_chain import generate_answer
from rag.retriever import CVE_ID_RE, retrieve

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _retrieve(question: str) -> list[dict]:
    """Route through the exact-ID bypass, else the LangChain semantic retriever."""
    if CVE_ID_RE.search(question):
        return retrieve(question)
    docs = get_retriever().invoke(question)
    return [{"text": d.page_content, "metadata": d.metadata} for d in docs]


def main() -> None:
    eval_path = Path("eval/eval_set.json")
    cache_path = Path("eval/demo_cache.json")

    # Load eval questions
    with eval_path.open() as f:
        eval_data = json.load(f)

    cache = {
        "generated_at": eval_data["generated_at"],
        "source": str(eval_path),
        "entries": []
    }

    for idx, entry in enumerate(eval_data["entries"], 1):
        question = entry["question"]
        logger.info(f"[{idx}/18] Processing: {question}")

        try:
            retrieved_chunks = _retrieve(question)
            result = generate_answer(question, retrieved_chunks)

            cache["entries"].append({
                "id": entry["id"],
                "question": question,
                "answer": result["answer"],
                "cited_cve_ids": result["cited_cve_ids"],
                "retrieved_count": len(retrieved_chunks)
            })
            logger.info(f"  ✓ Cached {len(result['cited_cve_ids'])} CVEs")
        except Exception as e:
            logger.error(f"  ✗ Failed: {e}")
            sys.exit(1)

    # Write cache
    with cache_path.open("w") as f:
        json.dump(cache, f, indent=2)

    logger.info(f"\n✓ Demo cache written to {cache_path}")


if __name__ == "__main__":
    main()
