"""
RAG Ingestion — chunks documents and stores embeddings in PostgreSQL + pgvector.

Supported source types:
  mitre        — ATT&CK technique entries
  sigma        — Detection rule documentation
  playbook     — SOC response playbooks
  cve          — CVE descriptions
  threat_report — External threat reports
  incident     — Historical incident summaries
"""
from __future__ import annotations

import uuid
from typing import List, Optional, Dict, Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.rag.embedder import embed_texts

log = structlog.get_logger()

CHUNK_SIZE = 512        # characters per chunk
CHUNK_OVERLAP = 64      # overlap between consecutive chunks


def chunk_text(
    content: str,
    source: str,
    source_id: str,
    metadata: Optional[Dict[str, Any]] = None,
    chunk_size: int = CHUNK_SIZE,
    overlap: int = CHUNK_OVERLAP,
) -> List[Dict]:
    """
    Split a document into overlapping chunks.
    Returns a list of dicts ready for embedding + storage.
    """
    content = content.strip()
    if not content:
        return []

    chunks = []
    start = 0
    while start < len(content):
        end = min(start + chunk_size, len(content))
        chunk_text_ = content[start:end].strip()
        if chunk_text_:
            chunks.append({
                "id": str(uuid.uuid4()),
                "source": source,
                "source_id": source_id,
                "content": chunk_text_,
                "metadata": metadata or {},
            })
        start += chunk_size - overlap

    return chunks


async def ingest_document(
    db: AsyncSession,
    content: str,
    source: str,
    source_id: str,
    metadata: Optional[Dict[str, Any]] = None,
    chunk_size: int = CHUNK_SIZE,
) -> int:
    """
    Chunk a document, embed chunks, and store in knowledge_chunks table.
    Returns the number of chunks stored.
    """
    chunks = chunk_text(content, source, source_id, metadata, chunk_size)
    if not chunks:
        return 0

    texts = [c["content"] for c in chunks]
    embeddings = embed_texts(texts)

    inserted = 0
    for chunk, embedding in zip(chunks, embeddings):
        await db.execute(
            text("""
                INSERT INTO knowledge_chunks (id, source, source_id, content, embedding, metadata)
                VALUES (:id, :source, :source_id, :content, :embedding, :metadata::jsonb)
                ON CONFLICT DO NOTHING
            """),
            {
                "id": chunk["id"],
                "source": chunk["source"],
                "source_id": chunk["source_id"],
                "content": chunk["content"],
                "embedding": str(embedding),          # pgvector accepts Python list as string
                "metadata": __import__("json").dumps(chunk["metadata"]),
            },
        )
        inserted += 1

    await db.flush()
    log.info("Document ingested", source=source, source_id=source_id, chunks=inserted)
    return inserted


async def ingest_batch_documents(
    db: AsyncSession,
    documents: List[Dict],
) -> int:
    """
    Ingest multiple documents at once.
    Each doc dict: {content, source, source_id, metadata?}
    """
    total = 0
    for doc in documents:
        n = await ingest_document(
            db,
            content=doc["content"],
            source=doc["source"],
            source_id=doc["source_id"],
            metadata=doc.get("metadata"),
        )
        total += n
    return total
