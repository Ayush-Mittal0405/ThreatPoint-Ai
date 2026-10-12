"""
RAG API endpoints.

POST /api/v1/rag/ingest      — ingest a document into the knowledge base
GET  /api/v1/rag/search      — semantic search (q=..., k=5, source=...)
GET  /api/v1/rag/stats       — knowledge base statistics
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.rag.ingestion import ingest_document
from app.rag.retriever import semantic_search

router = APIRouter()


class IngestRequest(BaseModel):
    content: str
    source: str           # mitre | sigma | playbook | cve | threat_report | incident
    source_id: str
    metadata: Optional[Dict[str, Any]] = None


class IngestResponse(BaseModel):
    source_id: str
    chunks_stored: int


class SearchResult(BaseModel):
    content: str
    source: str
    source_id: str
    metadata: Dict[str, Any]
    score: float


class SearchResponse(BaseModel):
    query: str
    results: List[SearchResult]


@router.post("/ingest", response_model=IngestResponse, status_code=201)
async def ingest_knowledge(
    body: IngestRequest,
    db: AsyncSession = Depends(get_db),
):
    """Ingest a knowledge document into the RAG knowledge base."""
    n = await ingest_document(
        db,
        content=body.content,
        source=body.source,
        source_id=body.source_id,
        metadata=body.metadata,
    )
    await db.commit()
    return IngestResponse(source_id=body.source_id, chunks_stored=n)


@router.get("/search", response_model=SearchResponse)
async def search_knowledge(
    q: str = Query(..., description="Search query"),
    k: int = Query(5, ge=1, le=20),
    source: Optional[str] = Query(None, description="Filter by source type"),
    db: AsyncSession = Depends(get_db),
):
    """Semantic search over the knowledge base."""
    results = await semantic_search(db, query=q, top_k=k, source_filter=source)
    return SearchResponse(
        query=q,
        results=[SearchResult(**r) for r in results],
    )


@router.get("/stats")
async def knowledge_stats(db: AsyncSession = Depends(get_db)):
    """Return knowledge base statistics."""
    result = await db.execute(
        text("SELECT source, COUNT(*) as count FROM knowledge_chunks GROUP BY source ORDER BY count DESC")
    )
    rows = result.fetchall()
    total = sum(r.count for r in rows)
    return {
        "total_chunks": total,
        "by_source": [{"source": r.source, "chunks": r.count} for r in rows],
    }
