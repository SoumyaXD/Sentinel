"""Embedding wrapper for local CVE chunk search."""

from __future__ import annotations

import tarfile
import tempfile
from pathlib import Path
from typing import Any, Protocol

import numpy as np
from transformers import AutoTokenizer


REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL_NAME = "all-MiniLM-L6-v2"
CHROMA_ONNX_ARCHIVE = Path.home() / ".cache" / "chroma" / "onnx_models" / MODEL_NAME / "onnx.tar.gz"
MODEL_CACHE_DIR = REPO_ROOT / "data" / ".model_cache" / MODEL_NAME
ONNX_MODEL_DIR = MODEL_CACHE_DIR / "onnx"


class _Encoder(Protocol):
    def encode(self, sentences: list[str] | str, **kwargs: Any) -> Any: ...


def _ensure_onnx_model_dir() -> Path:
    if (ONNX_MODEL_DIR / "model.onnx").exists():
        return ONNX_MODEL_DIR

    if not CHROMA_ONNX_ARCHIVE.exists():
        raise FileNotFoundError(
            "Local all-MiniLM-L6-v2 cache not found. Expected Chroma archive at "
            f"{CHROMA_ONNX_ARCHIVE}"
        )

    MODEL_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    ONNX_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=MODEL_CACHE_DIR) as temp_dir:
        temp_path = Path(temp_dir)
        with tarfile.open(CHROMA_ONNX_ARCHIVE, "r:gz") as archive:
            archive.extractall(temp_path)

        extracted_root = temp_path / "onnx"
        if not extracted_root.exists():
            raise FileNotFoundError("Chroma ONNX archive did not contain expected onnx/ directory")

        for item in extracted_root.iterdir():
            target = ONNX_MODEL_DIR / item.name
            if target.exists():
                continue
            if item.is_dir():
                import shutil

                shutil.copytree(item, target)
            else:
                import shutil

                shutil.copy2(item, target)

    return ONNX_MODEL_DIR


class _OnnxMiniLMEncoder:
    """Lightweight local ONNX encoder for the bundled all-MiniLM-L6-v2 model."""

    def __init__(self, model_dir: Path) -> None:
        import onnxruntime as ort

        self._tokenizer = AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True)
        self._session = ort.InferenceSession(
            str(model_dir / "model.onnx"),
            providers=["CPUExecutionProvider"],
        )
        self._input_names = {item.name for item in self._session.get_inputs()}

    def encode(self, sentences: list[str] | str, **_: Any) -> np.ndarray:
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
        return int(self._session.get_outputs()[0].shape[-1]) if self._session.get_outputs()[0].shape else 384


def _load_encoder() -> _Encoder:
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError as exc:  # pragma: no cover - environment issue
        raise RuntimeError("sentence-transformers is required to load the embedding model") from exc

    # Try the requested sentence-transformers path first.
    attempts: list[tuple[str, dict[str, Any]]] = [
        (MODEL_NAME, {"local_files_only": True}),
    ]

    # If a cached ONNX bundle is available, try the sentence-transformers ONNX backend too.
    try:
        model_dir = _ensure_onnx_model_dir()
    except Exception:
        model_dir = None

    if model_dir is not None:
        attempts.append((str(model_dir), {"backend": "onnx", "local_files_only": True}))

    last_error: Exception | None = None
    for model_name_or_path, kwargs in attempts:
        try:
            return SentenceTransformer(model_name_or_path, **kwargs)
        except Exception as exc:
            last_error = exc

    # Fall back to the local ONNX bundle so the repo can run without extra downloads.
    try:
        if model_dir is None:
            model_dir = _ensure_onnx_model_dir()
        return _OnnxMiniLMEncoder(model_dir)
    except Exception as exc:
        if last_error is not None:
            raise RuntimeError(
                "Unable to load all-MiniLM-L6-v2 with sentence-transformers or the local ONNX bundle"
            ) from exc
        raise


EMBEDDING_MODEL = _load_encoder()


def embed_text(text: str) -> list[float]:
    vector = EMBEDDING_MODEL.encode([text], convert_to_numpy=True)
    if isinstance(vector, np.ndarray):
        embedding = vector[0]
    else:
        embedding = np.asarray(vector, dtype=np.float32)[0]
    return [float(value) for value in embedding.tolist()]


def embed_texts(texts: list[str]) -> list[list[float]]:
    if not texts:
        return []
    vectors = EMBEDDING_MODEL.encode(texts, convert_to_numpy=True)
    if not isinstance(vectors, np.ndarray):
        vectors = np.asarray(vectors, dtype=np.float32)
    return [[float(value) for value in row.tolist()] for row in vectors]
