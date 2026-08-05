"""Minimal HuggingFace embeddings adapter for the local Stage A model."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from transformers import AutoTokenizer


@dataclass
class _OnnxMiniLMEncoder:
    model_dir: Path

    def __post_init__(self) -> None:
        import onnxruntime as ort

        self._tokenizer = AutoTokenizer.from_pretrained(str(self.model_dir), local_files_only=True)
        self._session = ort.InferenceSession(
            str(self.model_dir / "model.onnx"),
            providers=["CPUExecutionProvider"],
        )
        self._input_names = {item.name for item in self._session.get_inputs()}

    def encode(self, sentences: list[str] | str) -> np.ndarray:
        if isinstance(sentences, str):
            sentences = [sentences]
        if not sentences:
            return np.zeros((0, self.get_sentence_embedding_dimension()), dtype=np.float32)

        encoded = self._tokenizer(
            sentences,
            padding=True,
            truncation=True,
            return_tensors="np",
        )

        feed = {name: value for name, value in encoded.items() if name in self._input_names}
        outputs = self._session.run(None, feed)
        token_embeddings = np.asarray(outputs[0], dtype=np.float32)

        if token_embeddings.ndim == 2:
            embeddings = token_embeddings
        else:
            attention_mask = np.asarray(encoded["attention_mask"], dtype=np.float32)
            mask = attention_mask[..., None]
            summed = (token_embeddings * mask).sum(axis=1)
            counts = np.clip(mask.sum(axis=1), a_min=1e-9, a_max=None)
            embeddings = summed / counts

        return embeddings.astype(np.float32, copy=False)

    def get_sentence_embedding_dimension(self) -> int:
        output = self._session.get_outputs()[0]
        return int(output.shape[-1]) if output.shape else 384


@dataclass
class HuggingFaceEmbeddings:
    """LangChain-compatible embeddings wrapper backed by the cached ONNX model."""

    model_name: str
    model_kwargs: dict[str, Any] | None = None
    encode_kwargs: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        model_path = Path(self.model_name)
        if not model_path.exists():
            repo_root = Path(__file__).resolve().parents[1]
            model_path = repo_root / "data" / ".model_cache" / self.model_name / "onnx"
        if model_path.exists():
            self._encoder = _OnnxMiniLMEncoder(model_path)
            return

        raise RuntimeError(
            "The local ONNX embedding model could not be found. Expected a directory at "
            f"{model_path}"
        )

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        vectors = self._encoder.encode(texts)
        return [[float(value) for value in row.tolist()] for row in vectors]

    def embed_query(self, text: str) -> list[float]:
        vector = self._encoder.encode([text])[0]
        return [float(value) for value in vector.tolist()]
