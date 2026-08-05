"""LangChain wrappers around the persisted Stage A Chroma store."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    from langchain_chroma import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings
except ModuleNotFoundError as exc:  # pragma: no cover - environment setup issue
    Chroma = None
    HuggingFaceEmbeddings = None
    _LANGCHAIN_IMPORT_ERROR = exc
else:
    _LANGCHAIN_IMPORT_ERROR = None


REPO_ROOT = Path(__file__).resolve().parents[1]
CHROMA_DIR = REPO_ROOT / "data" / "chroma"
COLLECTION_NAME = "cve_chunks"
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
DEFAULT_K = 8


def _require_langchain() -> None:
    if _LANGCHAIN_IMPORT_ERROR is not None:
        raise RuntimeError(
            "LangChain dependencies are unavailable in the active Python environment. "
            "Install langchain, langchain-chroma, langchain-huggingface, and "
            "langchain-openai before using rag.chains."
        ) from _LANGCHAIN_IMPORT_ERROR


@lru_cache(maxsize=1)
def _get_embeddings() -> Any:
    _require_langchain()
    return HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL_NAME,
    )


@lru_cache(maxsize=1)
def get_vector_store() -> Any:
    """Return a LangChain Chroma client bound to the persisted Stage A store."""

    _require_langchain()
    return Chroma(
        collection_name=COLLECTION_NAME,
        persist_directory=str(CHROMA_DIR),
        embedding_function=_get_embeddings(),
    )


@lru_cache(maxsize=None)
def get_retriever(k: int = DEFAULT_K) -> Any:
    """Return a semantic retriever over the existing Chroma collection."""

    return get_vector_store().as_retriever(search_kwargs={"k": int(k)})
