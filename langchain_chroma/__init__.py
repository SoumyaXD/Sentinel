"""Minimal LangChain-style Chroma adapter over the persisted Stage A store."""

from __future__ import annotations

import json
import pickle
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np


@dataclass
class Document:
    page_content: str
    metadata: dict[str, Any]


class _Retriever:
    def __init__(self, store: "Chroma", k: int) -> None:
        self._store = store
        self._k = k

    def invoke(self, query: str) -> list[Document]:
        return self._store.similarity_search(query, k=self._k)


class Chroma:
    def __init__(
        self,
        *,
        collection_name: str,
        persist_directory: str | Path,
        embedding_function: Any,
        **_: Any,
    ) -> None:
        self._collection_name = collection_name
        self._persist_directory = Path(persist_directory)
        self._db_path = self._persist_directory / "chroma.sqlite3"
        self._embedding_function = embedding_function

        if not self._db_path.exists():
            raise FileNotFoundError(f"Persisted Chroma database not found at {self._db_path}")

        self._documents: list[str] = []
        self._metadatas: list[dict[str, Any]] = []
        self._normalized_embeddings: np.ndarray | None = None
        self._load_snapshot()

    def _load_snapshot(self) -> None:
        conn = sqlite3.connect(str(self._db_path))
        try:
            cur = conn.cursor()
            collection_row = cur.execute(
                "SELECT id, name FROM collections WHERE name = ?",
                (self._collection_name,),
            ).fetchone()
            if collection_row is None:
                raise RuntimeError(
                    f"Collection {self._collection_name!r} was not found in {self._db_path}"
                )
            collection_id = str(collection_row[0])

            vector_segment_row = cur.execute(
                """
                SELECT id
                FROM segments
                WHERE scope = 'VECTOR' AND collection = ?
                """,
                (collection_id,),
            ).fetchone()
            if vector_segment_row is None:
                raise RuntimeError(f"Vector segment for {self._collection_name!r} was not found")

            content_rows = cur.execute(
                """
                SELECT e.id, e.embedding_id, c.c0
                FROM embeddings AS e
                JOIN embedding_fulltext_search_content AS c ON c.id = e.id
                ORDER BY e.id
                """
            ).fetchall()
            metadata_rows = cur.execute(
                """
                SELECT id, key, string_value, int_value, float_value, bool_value
                FROM embedding_metadata
                ORDER BY id, key
                """
            ).fetchall()
            label_mapping_path = self._persist_directory / vector_segment_row[0] / "index_metadata.pickle"
            data_level0_path = self._persist_directory / vector_segment_row[0] / "data_level0.bin"
        finally:
            conn.close()

        if not label_mapping_path.exists():
            raise FileNotFoundError(f"Vector label mapping not found at {label_mapping_path}")
        if not data_level0_path.exists():
            raise FileNotFoundError(f"Vector data file not found at {data_level0_path}")

        with label_mapping_path.open("rb") as handle:
            index_metadata = pickle.load(handle)

        id_to_label = index_metadata.get("id_to_label", {})
        if not isinstance(id_to_label, dict):
            raise RuntimeError("Unexpected index metadata format: id_to_label is missing")

        metadata_by_id: dict[int, dict[str, Any]] = {}
        for row_id, key, string_value, int_value, float_value, bool_value in metadata_rows:
            row_metadata = metadata_by_id.setdefault(int(row_id), {})
            value: Any
            if string_value is not None:
                value = string_value
            elif int_value is not None:
                value = int_value
            elif float_value is not None:
                value = float_value
            elif bool_value is not None:
                value = bool(bool_value)
            else:
                value = None
            if value is not None:
                row_metadata[str(key)] = value

        # The Chroma HNSW data file uses a fixed 1,676-byte record layout:
        # 132 bytes of index bookkeeping, 1,536 bytes of float32 vector data,
        # and an 8-byte label at the tail.
        record_stride = 1676
        vector_offset = 132
        vector_size_bytes = 384 * 4

        blob = data_level0_path.read_bytes()
        if len(blob) % record_stride != 0:
            raise RuntimeError("Unexpected Chroma vector file size; cannot decode fixed-width records")

        total_records = len(blob) // record_stride
        records_by_label: dict[int, np.ndarray] = {}
        for index in range(total_records):
            start = index * record_stride
            record = memoryview(blob)[start : start + record_stride]
            label = int.from_bytes(record[-8:], "little", signed=False)
            vector = np.frombuffer(record[vector_offset : vector_offset + vector_size_bytes], dtype=np.float32).copy()
            records_by_label[label] = vector

        documents: list[str] = []
        metadatas: list[dict[str, Any]] = []
        embeddings: list[np.ndarray] = []

        for row_id, embedding_id, document in content_rows:
            row_id_int = int(row_id)
            raw_metadata = metadata_by_id.get(row_id_int, {})
            metadata_json = raw_metadata.get("metadata_json")
            if isinstance(metadata_json, str):
                try:
                    parsed_metadata = json.loads(metadata_json)
                except json.JSONDecodeError:
                    parsed_metadata = dict(raw_metadata)
            else:
                parsed_metadata = dict(raw_metadata)

            label = id_to_label.get(str(embedding_id))
            if label is None:
                continue

            vector = records_by_label.get(int(label))
            if vector is None:
                continue

            documents.append(str(document))
            metadatas.append(parsed_metadata if isinstance(parsed_metadata, dict) else {})
            embeddings.append(vector)

        if not embeddings:
            raise RuntimeError("Unable to match any stored vectors to documents in the Chroma snapshot")

        embedding_matrix = np.vstack(embeddings).astype(np.float32, copy=False)
        norms = np.linalg.norm(embedding_matrix, axis=1, keepdims=True)
        self._normalized_embeddings = embedding_matrix / np.clip(norms, a_min=1e-12, a_max=None)
        self._documents = documents
        self._metadatas = metadatas

    def as_retriever(self, search_kwargs: dict[str, Any] | None = None, **_: Any) -> _Retriever:
        k = 4
        if isinstance(search_kwargs, dict) and "k" in search_kwargs:
            try:
                k = int(search_kwargs["k"])
            except (TypeError, ValueError):
                k = 4
        return _Retriever(self, k)

    def similarity_search(self, query: str, k: int = 4) -> list[Document]:
        if self._normalized_embeddings is None:
            raise RuntimeError("The persisted Chroma snapshot has not been initialized")

        query_vector = np.asarray(self._embedding_function.embed_query(query), dtype=np.float32)
        query_norm = float(np.linalg.norm(query_vector))
        if query_norm > 0:
            query_vector = query_vector / query_norm

        scores = self._normalized_embeddings @ query_vector
        top_indices = np.argsort(-scores)[:k]

        return [
            Document(
                page_content=self._documents[index],
                metadata=self._metadatas[index],
            )
            for index in top_indices
        ]
