"""FastAPI service exposing the Sentinel RAG pipeline."""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.schemas import AskRequest, AskResponse
from rag.chains import CHROMA_DIR
from rag.generation_chain import generate_answer
from rag.retriever import retrieve_for_ask

logger = logging.getLogger(__name__)


def _rate_limit_string() -> str:
    """Return the rate-limit string from env, defaulting to '10/day'."""
    raw = os.getenv("RATE_LIMIT_PER_DAY", "")
    try:
        value = int(raw)
        if value > 0:
            return f"{value}/day"
    except (ValueError, TypeError):
        pass
    return "10/day"


RATE_LIMIT_STRING = _rate_limit_string()

limiter = Limiter(key_func=get_remote_address)

# Load demo cache at startup
DEMO_CACHE_PATH = Path("eval/demo_cache.json")
DEMO_CACHE: dict[str, dict] = {}

if DEMO_CACHE_PATH.exists():
    with DEMO_CACHE_PATH.open() as f:
        cache_data = json.load(f)
        # Build a normalized-question-to-answer mapping
        for entry in cache_data.get("entries", []):
            # Store by normalized question: lowercase, strip whitespace and trailing punctuation
            normalized_q = entry["question"].lower().strip().rstrip("?.!")
            DEMO_CACHE[normalized_q] = {
                "answer": entry["answer"],
                "cited_cve_ids": entry["cited_cve_ids"],
                "retrieved_count": entry["retrieved_count"]
            }
    logger.info(f"Loaded {len(DEMO_CACHE)} demo cache entries from {DEMO_CACHE_PATH}")


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
        content={"detail": "Rate limit exceeded. Try again tomorrow."},
    ),
)
app.add_middleware(SlowAPIMiddleware)


@app.get("/health", response_model=None, description="Health check endpoint verifying that OPENAI_API_KEY is set and the Chroma vector store is accessible.")
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


@app.post("/ask/demo", response_model=AskResponse, description="Demo endpoint serving pre-cached answers for the 18 evaluation questions from eval/eval_set.json. Returns instantly with no API cost and no rate limit. If the question doesn't match a cached entry, returns 400 with guidance to use POST /ask instead.")
def ask_demo(body: AskRequest) -> AskResponse:
    """Serve pre-cached demo answers for the 18 eval questions."""
    # Normalize: lowercase, strip whitespace and trailing punctuation
    normalized_q = body.question.lower().strip().rstrip("?.!")
    
    if normalized_q in DEMO_CACHE:
        cached = DEMO_CACHE[normalized_q]
        return AskResponse(
            answer=cached["answer"],
            cited_cve_ids=cached["cited_cve_ids"],
            retrieved_count=cached["retrieved_count"]
        )
    
    # Not in cache
    raise HTTPException(
        status_code=400,
        detail=(
            "This demo endpoint only serves the 18 pre-set evaluation questions from eval/eval_set.json. "
            "Your question was not recognized. To ask a custom question, use POST /ask instead (subject to rate limits)."
        )
    )


@app.post("/ask", response_model=AskResponse, description="Submit a custom CVE security question. This endpoint runs the full RAG pipeline with real-time retrieval and OpenAI generation. Subject to rate limiting (10 requests per IP per day by default).")
@limiter.limit(RATE_LIMIT_STRING)
def ask(request: Request, body: AskRequest) -> AskResponse:
    question = body.question.strip()
    if not question:
        raise HTTPException(status_code=422, detail="question must not be empty.")

    try:
        retrieved_chunks = retrieve_for_ask(question)
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
