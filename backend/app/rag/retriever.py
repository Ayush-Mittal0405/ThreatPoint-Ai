"""
RAG Retriever — semantic search over the knowledge_chunks table using pgvector.

Uses cosine similarity (vector_cosine_ops).
"""
from __future__ import annotations

import json
from typing import List, Optional, Dict, Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.rag.embedder import embed_single

log = structlog.get_logger()


async def semantic_search(
    db: AsyncSession,
    query: str,
    top_k: int = 5,
    source_filter: Optional[str] = None,
    min_score: float = 0.3,
) -> List[Dict[str, Any]]:
    """
    Find the top-k most semantically similar knowledge chunks to `query`.

    Args:
        query: Natural-language search query
        top_k: Number of results to return
        source_filter: Restrict to a specific source (e.g. 'mitre', 'playbook')
        min_score: Minimum cosine similarity threshold (0-1)

    Returns:
        List of dicts with: content, source, source_id, metadata, score
    """
    query_embedding = embed_single(query)
    embedding_str = str(query_embedding)

    if source_filter:
        sql = text("""
            SELECT
                content,
                source,
                source_id,
                metadata,
                1 - (embedding <=> :embedding::vector) AS score
            FROM knowledge_chunks
            WHERE source = :source
              AND 1 - (embedding <=> :embedding::vector) >= :min_score
            ORDER BY embedding <=> :embedding::vector
            LIMIT :top_k
        """)
        params = {
            "embedding": embedding_str,
            "source": source_filter,
            "min_score": min_score,
            "top_k": top_k,
        }
    else:
        sql = text("""
            SELECT
                content,
                source,
                source_id,
                metadata,
                1 - (embedding <=> :embedding::vector) AS score
            FROM knowledge_chunks
            WHERE 1 - (embedding <=> :embedding::vector) >= :min_score
            ORDER BY embedding <=> :embedding::vector
            LIMIT :top_k
        """)
        params = {
            "embedding": embedding_str,
            "min_score": min_score,
            "top_k": top_k,
        }

    result = await db.execute(sql, params)
    rows = result.fetchall()

    chunks = []
    for row in rows:
        meta = row.metadata
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        chunks.append({
            "content": row.content,
            "source": row.source,
            "source_id": row.source_id,
            "metadata": meta,
            "score": round(float(row.score), 4),
        })

    log.info("RAG search", query=query[:60], results=len(chunks))
    return chunks


async def rag_context_for_query(
    db: AsyncSession,
    query: str,
    top_k: int = 5,
    source_filter: Optional[str] = None,
) -> str:
    """
    High-level helper: returns a formatted string of retrieved context
    ready to inject into an LLM prompt.
    """
    results = await semantic_search(db, query, top_k=top_k, source_filter=source_filter)
    if not results:
        return "No relevant knowledge found in the knowledge base."

    parts = []
    for i, r in enumerate(results, 1):
        parts.append(
            f"[Source {i}: {r['source']} / {r['source_id']} (score={r['score']})]\n{r['content']}"
        )
    return "\n\n---\n\n".join(parts)
