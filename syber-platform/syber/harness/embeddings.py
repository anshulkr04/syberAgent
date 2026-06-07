"""
Text embeddings used by the TI integrity check, RAG anomaly check, and
self-consistency scoring (spec 9.2, 10.2, 12.2).

The spec uses an SBERT model. sentence-transformers depends on torch, which has
no Python 3.14 wheel, so the default is a deterministic hashed character-n-gram
embedding that yields a usable cosine geometry (identical text -> 1.0, unrelated
text -> ~0). Set SYBER_SBERT_MODEL to swap in a real SBERT encoder.

The function name `encode` and the cosine helper match the spec's call sites.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Callable

import numpy as np

_DIM = 384


def _stable_hash(token: str) -> int:
    """Process-stable hash (builtin hash() is randomised by PYTHONHASHSEED,
    which would make embeddings — and learned thresholds — non-reproducible)."""
    return int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big")


def _hashed_ngram_encode(text: str) -> np.ndarray:
    vec = np.zeros(_DIM, dtype=np.float64)
    tokens = re.findall(r"\w+", (text or "").lower())
    # unigrams + bigrams give a reasonable lexical-semantic proxy
    grams = tokens + [f"{a}_{b}" for a, b in zip(tokens, tokens[1:])]
    for g in grams:
        idx = _stable_hash("syber::" + g) % _DIM
        vec[idx] += 1.0
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


_encoder: Callable[[str], np.ndarray] = _hashed_ngram_encode


def _try_load_sbert() -> None:
    model_id = os.environ.get("SYBER_SBERT_MODEL")
    if not model_id:
        return
    try:  # pragma: no cover
        from sentence_transformers import SentenceTransformer

        model = SentenceTransformer(model_id)

        def _sbert_encode(text: str) -> np.ndarray:
            return np.asarray(model.encode(text), dtype=np.float64)

        global _encoder
        _encoder = _sbert_encode
    except Exception:  # noqa: BLE001
        pass


_try_load_sbert()


def encode(text: str) -> np.ndarray:
    return _encoder(text)


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def cosine_distance(a: np.ndarray, b: np.ndarray) -> float:
    return 1.0 - cosine_similarity(a, b)


def centroid(texts: list[str]) -> np.ndarray:
    if not texts:
        return np.zeros(_DIM)
    mat = np.vstack([encode(t) for t in texts])
    c = mat.mean(axis=0)
    n = np.linalg.norm(c)
    return c / n if n > 0 else c
