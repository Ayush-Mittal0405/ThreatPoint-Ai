"""
MITRE ATT&CK Ingestion Script
Downloads the MITRE ATT&CK Enterprise JSON from GitHub and ingests
all techniques into the AegisX RAG knowledge base.

Usage:
    python scripts/ingestion/ingest_mitre.py

Requires the backend to be running (or direct DB access via .env).
"""
from __future__ import annotations

import asyncio
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))

import httpx
import structlog
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

from app.core.database import AsyncSessionLocal
from app.rag.ingestion import ingest_document

log = structlog.get_logger()

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def _technique_to_text(technique: dict) -> str:
    """Convert a MITRE technique object to a searchable text document."""
    ext_refs = technique.get("external_references", [])
    tid = next((r.get("external_id", "") for r in ext_refs if r.get("source_name") == "mitre-attack"), "")
    url  = next((r.get("url", "")          for r in ext_refs if r.get("source_name") == "mitre-attack"), "")

    name        = technique.get("name", "")
    description = technique.get("description", "")
    platforms   = ", ".join(technique.get("x_mitre_platforms", []))
    detection   = technique.get("x_mitre_detection", "")
    data_sources= ", ".join(technique.get("x_mitre_data_sources", []))

    kill_chain  = []
    for phase in technique.get("kill_chain_phases", []):
        kill_chain.append(phase.get("phase_name", ""))
    tactics = ", ".join(kill_chain)

    return f"""MITRE ATT&CK Technique: {tid} — {name}

Tactics: {tactics}
Platforms: {platforms}
Data Sources: {data_sources}

Description:
{description}

Detection:
{detection}

Reference: {url}
""".strip()


async def run():
    log.info("Downloading MITRE ATT&CK Enterprise dataset...")
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(MITRE_URL)
        resp.raise_for_status()
        data = resp.json()

    objects = data.get("objects", [])
    techniques = [
        o for o in objects
        if o.get("type") == "attack-pattern"
        and not o.get("x_mitre_deprecated", False)
        and not o.get("revoked", False)
    ]
    log.info(f"Found {len(techniques)} active techniques")

    total_chunks = 0
    async with AsyncSessionLocal() as db:
        for i, tech in enumerate(techniques):
            ext_refs = tech.get("external_references", [])
            tid = next(
                (r.get("external_id", f"T-{i}") for r in ext_refs if r.get("source_name") == "mitre-attack"),
                f"T-{i}",
            )
            content = _technique_to_text(tech)
            metadata = {
                "technique_id": tid,
                "name": tech.get("name"),
                "tactics": [p.get("phase_name") for p in tech.get("kill_chain_phases", [])],
                "platforms": tech.get("x_mitre_platforms", []),
            }
            n = await ingest_document(
                db, content=content,
                source="mitre", source_id=tid, metadata=metadata,
            )
            total_chunks += n
            if (i + 1) % 50 == 0:
                log.info(f"Progress: {i+1}/{len(techniques)} techniques ingested")
                await db.commit()

        await db.commit()

    log.info(f"MITRE ingestion complete. Techniques: {len(techniques)}, Chunks: {total_chunks}")


if __name__ == "__main__":
    asyncio.run(run())
