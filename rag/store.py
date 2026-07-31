"""Persistent Chroma vector store for normalized CVE chunks."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    import chromadb
except ModuleNotFoundError:  # pragma: no cover - exercised in environments without chromadb
    chromadb = None

from rag.chunk import chunk_cve_record


REPO_ROOT = Path(__file__).resolve().parents[1]
CHROMA_DIR = REPO_ROOT / "data" / "chroma"
NORMALIZED_CVES_PATH = REPO_ROOT / "data" / "normalized" / "all_cves.json"
COLLECTION_NAME = "cve_chunks"

if chromadb is not None:
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    CHROMA_CLIENT = chromadb.PersistentClient(path=str(CHROMA_DIR))
    CHROMA_COLLECTION = CHROMA_CLIENT.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )
else:  # pragma: no cover - simple import-time fallback
    CHROMA_CLIENT = None
    CHROMA_COLLECTION = None


def _load_normalized_records() -> list[dict[str, Any]]:
    if NORMALIZED_CVES_PATH.exists():
        with NORMALIZED_CVES_PATH.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        if not isinstance(payload, list):
            raise ValueError("Expected data/normalized/all_cves.json to contain a list of records")

        return [item for item in payload if isinstance(item, dict)]

    from ingest.normalize import normalize_records

    return normalize_records()


@lru_cache(maxsize=1)
def _fallback_chunks() -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    for record in _load_normalized_records():
        chunks.extend(chunk_cve_record(record))
    return chunks


def _chunk_id(chunk: dict[str, Any], index: int) -> str:
    metadata = chunk.get("metadata", {})
    cve_id = str(metadata.get("cve_id", "unknown_cve")).strip() or "unknown_cve"
    chunk_type = str(metadata.get("chunk_type", f"chunk_{index}")).strip() or f"chunk_{index}"
    safe_chunk_type = chunk_type.replace("/", "_").replace(":", "_").replace(" ", "_")
    return f"{cve_id}_{safe_chunk_type}"


def _stored_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    stored: dict[str, Any] = {
        "cve_id": str(metadata.get("cve_id", "")).strip(),
        "chunk_type": str(metadata.get("chunk_type", "")).strip(),
        "cvss_score": metadata.get("cvss_score"),
        "cvss_severity": str(metadata.get("cvss_severity", "")).strip(),
        "metadata_json": json.dumps(metadata, ensure_ascii=False, sort_keys=True),
    }
    if "section_name" in metadata:
        stored["section_name"] = str(metadata["section_name"]).strip()
    return {key: value for key, value in stored.items() if value not in (None, "", [])}


def _search_text(chunk: dict[str, Any]) -> str:
    metadata = chunk.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    affected_packages = metadata.get("affected_packages", [])
    package_names: list[str] = []
    if isinstance(affected_packages, list):
        for package in affected_packages:
            if not isinstance(package, dict):
                continue
            name = str(package.get("name", "")).strip()
            ecosystem = str(package.get("ecosystem", "")).strip()
            if name:
                package_names.append(name)
            if ecosystem:
                package_names.append(ecosystem)

    parts = [
        str(chunk.get("text", "")),
        str(metadata.get("cve_id", "")),
        str(metadata.get("chunk_type", "")),
        str(metadata.get("cvss_score", "")),
        str(metadata.get("cvss_severity", "")),
        " ".join(package_names),
    ]
    return " ".join(part for part in parts if part).strip()


def add_chunks(chunks: list[dict[str, Any]]) -> int:
    if chromadb is None:
        raise RuntimeError("chromadb is not installed; persistent store embedding is unavailable")
    from rag.embed import embed_text

    if not chunks:
        return 0

    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict[str, Any]] = []
    embeddings: list[list[float]] = []
    seen_base_ids: dict[str, int] = {}

    for index, chunk in enumerate(chunks):
        metadata = chunk.get("metadata", {})
        base_id = _chunk_id(chunk, index)
        occurrence = seen_base_ids.get(base_id, 0) + 1
        seen_base_ids[base_id] = occurrence
        ids.append(base_id if occurrence == 1 else f"{base_id}_{occurrence}")
        text = str(chunk.get("text", ""))
        documents.append(text)
        metadatas.append(_stored_metadata(metadata if isinstance(metadata, dict) else {}))
        embeddings.append(embed_text(text))

    CHROMA_COLLECTION.upsert(
        ids=ids,
        embeddings=embeddings,
        documents=documents,
        metadatas=metadatas,
    )
    return len(chunks)


def query(text: str, k: int = 5) -> list[dict[str, Any]]:
    if chromadb is None:
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.metrics.pairwise import cosine_similarity
        except ModuleNotFoundError as exc:  # pragma: no cover - only in very small environments
            raise RuntimeError("scikit-learn is required for fallback semantic search") from exc

        chunks = _fallback_chunks()
        if not chunks:
            return []

        corpus = [_search_text(chunk) for chunk in chunks]
        vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
        matrix = vectorizer.fit_transform(corpus + [text])
        similarities = cosine_similarity(matrix[:-1], matrix[-1]).ravel()
        ranked = sorted(enumerate(similarities), key=lambda item: item[1], reverse=True)[:k]

        output: list[dict[str, Any]] = []
        for index, similarity in ranked:
            chunk = chunks[index]
            distance = 1.0 - float(similarity)
            output.append(
                {
                    "id": _chunk_id(chunk, index),
                    "text": chunk.get("text", ""),
                    "metadata": chunk.get("metadata", {}),
                    "distance": distance,
                    "similarity": float(similarity),
                }
            )
        return output

    query_embedding = embed_text(text)
    results = CHROMA_COLLECTION.query(
        query_embeddings=[query_embedding],
        n_results=k,
        include=["documents", "metadatas", "distances"],
    )

    ids = results.get("ids", [[]])[0]
    documents = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]

    output: list[dict[str, Any]] = []
    for idx, doc, metadata, distance in zip(ids, documents, metadatas, distances):
        parsed_metadata: dict[str, Any]
        if isinstance(metadata, dict) and metadata.get("metadata_json"):
            try:
                parsed_metadata = json.loads(metadata["metadata_json"])
            except (TypeError, json.JSONDecodeError):
                parsed_metadata = metadata
        else:
            parsed_metadata = metadata if isinstance(metadata, dict) else {}

        similarity = None
        if distance is not None:
            try:
                similarity = 1.0 - float(distance)
            except (TypeError, ValueError):
                similarity = None

        output.append(
            {
                "id": idx,
                "text": doc,
                "metadata": parsed_metadata,
                "distance": distance,
                "similarity": similarity,
            }
        )

    return output


def _build_all_chunks() -> list[dict[str, Any]]:
    return _fallback_chunks()


def main() -> None:
    chunks = _build_all_chunks()
    embedded = add_chunks(chunks)
    print(f"Total chunks embedded: {embedded}")
    print(f"Persistent Chroma path: {CHROMA_DIR}")


if __name__ == "__main__":
    main()
