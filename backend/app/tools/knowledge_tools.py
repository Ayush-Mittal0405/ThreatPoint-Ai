"""
Knowledge tools — MITRE ATT&CK lookups (via RAG), knowledge base search, and attack graph queries.
Phase 5: real pgvector RAG retrieval replaces the static stub.
"""
from __future__ import annotations

from typing import Dict, List, Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.rag.retriever import semantic_search, rag_context_for_query

log = structlog.get_logger()

# Fallback static entries for when DB has no data yet
_STATIC_MITRE: Dict[str, Dict] = {
    "T1059.001": {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
    "T1566.001": {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1027":     {"id": "T1027",     "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1571":     {"id": "T1571",     "name": "Non-Standard Port", "tactic": "Command and Control"},
    "T1098":     {"id": "T1098",     "name": "Account Manipulation", "tactic": "Persistence"},
    "T1036.005": {"id": "T1036.005", "name": "Match Legitimate Name or Location", "tactic": "Defense Evasion"},
}


class KnowledgeTools:
    """Security knowledge retrieval — backed by pgvector RAG."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def search_mitre_technique(self, technique_id: str) -> Dict:
        """
        Look up a MITRE ATT&CK technique by ID using RAG.
        Falls back to static dict if knowledge base is empty.
        """
        technique_id = technique_id.upper().strip()

        # Try RAG first (populated after running ingest_mitre.py)
        try:
            results = await semantic_search(
                self.db,
                query=f"MITRE ATT&CK technique {technique_id}",
                top_k=3,
                source_filter="mitre",
                min_score=0.5,
            )
            # Find exact match by technique_id in metadata
            for r in results:
                if r.get("metadata", {}).get("technique_id") == technique_id:
                    return {
                        "found": True,
                        "source": "rag",
                        "technique_id": technique_id,
                        "name": r["metadata"].get("name"),
                        "tactics": r["metadata"].get("tactics", []),
                        "platforms": r["metadata"].get("platforms", []),
                        "description": r["content"],
                        "score": r["score"],
                    }
            # No exact match — return best semantic result
            if results:
                r = results[0]
                return {
                    "found": True,
                    "source": "rag",
                    "partial_match": True,
                    "technique_id": r["metadata"].get("technique_id", technique_id),
                    "name": r["metadata"].get("name"),
                    "tactics": r["metadata"].get("tactics", []),
                    "description": r["content"],
                    "score": r["score"],
                }
        except Exception as exc:
            log.warning("RAG MITRE lookup failed, using static fallback", error=str(exc))

        # Static fallback
        tech = _STATIC_MITRE.get(technique_id)
        if tech:
            return {"found": True, "source": "static", **tech}

        # Prefix match
        matches = [v for k, v in _STATIC_MITRE.items() if k.startswith(technique_id)]
        if matches:
            return {"found": True, "source": "static", "partial_match": True, "techniques": matches}

        return {"found": False, "technique_id": technique_id, "note": "Not found. Run scripts/ingestion/ingest_mitre.py to load full ATT&CK database."}

    async def search_rag(self, query: str, top_k: int = 5, source: Optional[str] = None) -> Dict:
        """Semantic search over the full knowledge base."""
        log.info("RAG search", query=query[:80])
        try:
            results = await semantic_search(
                self.db, query=query, top_k=top_k, source_filter=source
            )
            return {
                "query": query,
                "results": results,
                "count": len(results),
            }
        except Exception as exc:
            log.warning("RAG search failed", error=str(exc))
            return {"query": query, "results": [], "count": 0, "error": str(exc)}

    async def query_attack_graph(self, entity_type: str, entity_value: str) -> Dict:
        """Query the security knowledge graph for entity relationships. Phase 6."""
        log.info("Attack graph query", entity_type=entity_type, entity=entity_value)
        return {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "relationships": [],
            "note": "Knowledge graph implemented in Phase 6 (NetworkX/Neo4j).",
        }
