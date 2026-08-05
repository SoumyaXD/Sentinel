"""LangChain wrappers around the persisted Stage A Chroma store."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from rag.embed import embed_text, embed_texts

try:
    from langchain_chroma import Chroma
    from langchain_core.embeddings import Embeddings
except ModuleNotFoundError as exc:  # pragma: no cover - environment setup issue
    Chroma = None
    Embeddings = None
    _LANGCHAIN_IMPORT_ERROR = exc
else:
    _LANGCHAIN_IMPORT_ERROR = None


REPO_ROOT = Path(__file__).resolve().parents[1]
CHROMA_DIR = REPO_ROOT / "data" / "chroma"
COLLECTION_NAME = "cve_chunks"
DEFAULT_K = 8


class SentinelEmbeddings(Embeddings):
    """LangChain adapter backed by Sentinel's Stage A embedding pipeline."""

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return embed_texts(texts)

    def embed_query(self, text: str) -> list[float]:
        return embed_text(text)


def _require_langchain() -> None:
    """Raise a clear error if LangChain dependencies are unavailable."""

    if _LANGCHAIN_IMPORT_ERROR is not None:
        raise RuntimeError(
            "Missing LangChain dependencies. Install "
            "'langchain', 'langchain-core', "
            "'langchain-chroma', and 'langchain-openai'."
        ) from _LANGCHAIN_IMPORT_ERROR


@lru_cache(maxsize=1)
def _get_embeddings() -> SentinelEmbeddings:
    """Return the shared LangChain embedding adapter."""

    _require_langchain()
    return SentinelEmbeddings()


@lru_cache(maxsize=1)
def get_vector_store() -> Chroma:
    """Return a LangChain Chroma client bound to the persisted Stage A store."""

    _require_langchain()

    if not CHROMA_DIR.exists():
        raise FileNotFoundError(
            f"Persisted Chroma store not found: {CHROMA_DIR}"
        )

    return Chroma(
        collection_name=COLLECTION_NAME,
        persist_directory=str(CHROMA_DIR),
        embedding_function=_get_embeddings(),
    )


@lru_cache(maxsize=None)
def get_retriever(k: int = DEFAULT_K):
    """Return a semantic retriever over the existing Chroma collection."""

    return get_vector_store().as_retriever(
        search_kwargs={"k": int(k)}
    )


__all__ = [
    "SentinelEmbeddings",
    "get_vector_store",
    "get_retriever",
]