"""
Unit tests for the RAG Pipeline (Embedder, Ingestion Chunking, and Retriever).
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.rag.ingestion import chunk_text, CHUNK_SIZE, CHUNK_OVERLAP
from app.rag.embedder import embed_texts, embed_single, EMBEDDING_DIM
from app.rag.retriever import semantic_search, rag_context_for_query


class TestRAGChunking:
    def test_empty_content_returns_empty_list(self):
        chunks = chunk_text("", source="mitre", source_id="T1059")
        assert chunks == []

    def test_short_content_single_chunk(self):
        text = "PowerShell is a cross-platform command-line shell and scripting language."
        chunks = chunk_text(text, source="mitre", source_id="T1059.001", metadata={"technique": "PowerShell"})
        assert len(chunks) == 1
        assert chunks[0]["source"] == "mitre"
        assert chunks[0]["source_id"] == "T1059.001"
        assert chunks[0]["content"] == text
        assert chunks[0]["metadata"]["technique"] == "PowerShell"

    def test_long_content_multi_chunks(self):
        text = "A" * 1200
        chunks = chunk_text(text, source="threat_report", source_id="TR-001", chunk_size=500, overlap=50)
        assert len(chunks) >= 3
        for c in chunks:
            assert len(c["content"]) <= 500

    def test_chunk_overlap_preserved(self):
        words = ["word" + str(i) for i in range(100)]
        content = " ".join(words)
        chunks = chunk_text(content, source="playbook", source_id="PB-01", chunk_size=100, overlap=20)
        assert len(chunks) > 1
        assert chunks[0]["content"][-15:] in chunks[1]["content"][:50]


class TestRAGEmbedder:
    def test_embed_single_dimension(self):
        vec = embed_single("Test security alert telemetry")
        assert isinstance(vec, list)
        assert len(vec) == EMBEDDING_DIM
        assert all(isinstance(x, float) for x in vec)

    def test_embed_texts_batch(self):
        texts = ["Incident INC-001", "MITRE ATT&CK T1059.001", "Zeek conn.log alert"]
        vecs = embed_texts(texts)
        assert len(vecs) == 3
        for v in vecs:
            assert len(v) == EMBEDDING_DIM

    def test_embed_fallback_when_model_none(self):
        with patch("app.rag.embedder._get_model", return_value=None):
            vecs = embed_texts(["Test"])
            assert len(vecs) == 1
            assert len(vecs[0]) == EMBEDDING_DIM
            assert all(x == 0.0 for x in vecs[0])


class TestRAGRetriever:
    def test_semantic_search_success(self):
        async def _run():
            mock_db = AsyncMock()
            mock_row = MagicMock()
            mock_row.content = "PowerShell execution via Office macro"
            mock_row.source = "mitre"
            mock_row.source_id = "T1059.001"
            mock_row.metadata = {"name": "PowerShell"}
            mock_row.score = 0.88

            mock_result = MagicMock()
            mock_result.fetchall.return_value = [mock_row]
            mock_db.execute.return_value = mock_result

            results = await semantic_search(mock_db, query="macro powershell execution", top_k=2)
            assert len(results) == 1
            assert results[0]["source_id"] == "T1059.001"
            assert results[0]["score"] == 0.88
        asyncio.run(_run())

    def test_rag_context_for_query_format(self):
        async def _run():
            mock_db = AsyncMock()
            mock_row = MagicMock()
            mock_row.content = "Adversaries may abuse PowerShell commands."
            mock_row.source = "mitre"
            mock_row.source_id = "T1059.001"
            mock_row.metadata = {}
            mock_row.score = 0.92

            mock_result = MagicMock()
            mock_result.fetchall.return_value = [mock_row]
            mock_db.execute.return_value = mock_result

            ctx = await rag_context_for_query(mock_db, query="powershell")
            assert "T1059.001" in ctx
            assert "Adversaries may abuse PowerShell" in ctx
        asyncio.run(_run())
