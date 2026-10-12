"""
RAG Embedder — converts text chunks into vector embeddings.

Uses sentence-transformers (all-MiniLM-L6-v2, 384-dim) locally.
No external API calls — all computation is local.
"""
from __future__ import annotations

from functools import lru_cache
from typing import List

import structlog

log = structlog.get_logger()

MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384


@lru_cache(maxsize=1)
def _get_model():
    """Lazy-load sentence-transformers model (cached after first call)."""
    try:
        from sentence_transformers import SentenceTransformer
        log.info("Loading embedding model", model=MODEL_NAME)
        model = SentenceTransformer(MODEL_NAME)
        log.info("Embedding model loaded")
        return model
    except ImportError:
        log.warning("sentence-transformers not installed — RAG disabled. Run: pip install sentence-transformers")
        return None


def embed_texts(texts: List[str]) -> List[List[float]]:
    """
    Embed a list of text strings.
    Returns a list of 384-dim float vectors.
    Falls back to zero vectors if model unavailable.
    """
    model = _get_model()
    if model is None:
        log.warning("Returning zero embeddings — sentence-transformers unavailable")
        return [[0.0] * EMBEDDING_DIM for _ in texts]

    embeddings = model.encode(texts, show_progress_bar=False, convert_to_numpy=True)
    return embeddings.tolist()


def embed_single(text: str) -> List[float]:
    """Embed a single string."""
    return embed_texts([text])[0]
