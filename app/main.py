"""FastAPI service exposing the Sentinel RAG pipeline."""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException

from app.schemas import AskRequest, AskResponse
from rag.chains import get_retriever
from rag.generation_chain import generate_answer
from rag.retriever import CVE_ID_RE, retrieve

logger = logging.getLogger(__name__)

app = FastAPI(title="Sentinel", description="CVE research and patch-prioritization RAG API.")


def _retrieve(question: str) -> list[dict]:
    """Route through the exact-ID bypass, else the LangChain semantic retriever."""
    if CVE_ID_RE.search(question):
        return retrieve(question)
    docs = get_retriever().invoke(question)
    return [{"text": d.page_content, "metadata": d.metadata} for d in docs]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/ask", response_model=AskResponse)
def ask(request: AskRequest) -> AskResponse:
    question = request.question.strip()
    if not question:
        raise HTTPException(status_code=422, detail="question must not be empty.")

    try:
        retrieved_chunks = _retrieve(question)
    except Exception:
        logger.exception("Retrieval failed for question: %r", question)
        raise HTTPException(status_code=500, detail="Retrieval failed. Check server logs.") from None

    try:
        result = generate_answer(question, retrieved_chunks)
    except Exception:
        logger.exception("Generation failed for question: %r", question)
        raise HTTPException(status_code=500, detail="Answer generation failed. Check server logs.") from None

    return AskResponse(
        answer=result["answer"],
        cited_cve_ids=result["cited_cve_ids"],
        retrieved_count=len(retrieved_chunks),
    )