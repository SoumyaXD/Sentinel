"""FastAPI service exposing the Sentinel RAG pipeline."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import _SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.schemas import AskRequest, AskResponse
from rag.chains import CHROMA_DIR, get_retriever
from rag.generation_chain import generate_answer
from rag.retriever import CVE_ID_RE, retrieve

logger = logging.getLogger(__name__)


def _rate_limit_string() -> str:
    """Return the rate-limit string from env, defaulting to '10/minute'."""
    raw = os.getenv("RATE_LIMIT_PER_MINUTE", "")
    try:
        value = int(raw)
        if value > 0:
            return f"{value}/minute"
    except (ValueError, TypeError):
        pass
    return "10/minute"


RATE_LIMIT_STRING = _rate_limit_string()

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup validation: ensure OPENAI_API_KEY is present."""
    if not os.getenv("OPENAI_API_KEY", "").strip():
        logger.error("OPENAI_API_KEY is not set. Refusing to start.")
        raise RuntimeError("OPENAI_API_KEY is not set. Refusing to start.")
    yield


app = FastAPI(
    title="Sentinel",
    description="CVE research and patch-prioritization RAG API.",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    lambda request, exc: JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Try again in a minute."},
    ),
)
app.add_middleware(_SlowAPIMiddleware)


def _retrieve(question: str) -> list[dict]:
    """Route through the exact-ID bypass, else the LangChain semantic retriever."""
    if CVE_ID_RE.search(question):
        return retrieve(question)
    docs = get_retriever().invoke(question)
    return [{"text": d.page_content, "metadata": d.metadata} for d in docs]


@app.get("/health")
def health() -> JSONResponse | dict[str, str]:
    if not os.getenv("OPENAI_API_KEY", "").strip():
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "reason": "OPENAI_API_KEY is not set"},
        )
    try:
        chroma_ok = CHROMA_DIR.exists() and any(CHROMA_DIR.iterdir())
    except OSError:
        chroma_ok = False
    if not chroma_ok:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "reason": "Chroma store is missing or empty"},
        )
    return {"status": "ok"}


@app.post("/ask", response_model=AskResponse)
@limiter.limit(RATE_LIMIT_STRING)
def ask(request: Request, body: AskRequest) -> AskResponse:
    question = body.question.strip()
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
