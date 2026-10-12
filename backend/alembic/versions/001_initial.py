"""
Alembic migration: 001_initial

Creates all AegisX tables from scratch:
  - normalized_events
  - detection_rules
  - alerts
  - alert_events  (join table)
  - incidents
  - agent_traces

Also enables the pgvector extension for RAG embeddings.

To apply:
    cd aegisx/backend
    alembic upgrade head

To generate a new migration after model changes:
    alembic revision --autogenerate -m "describe change"
"""
from __future__ import annotations

import uuid
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

# ── Migration metadata ────────────────────────────────────────────────────────
revision = "001_initial"
down_revision = None        # first migration — no parent
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all AegisX tables."""

    # pgvector extension (required for RAG embeddings; no-op if already exists)
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # ── normalized_events ─────────────────────────────────────────────────────
    op.create_table(
        "normalized_events",
        sa.Column("id",             UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("event_id",       sa.String(128),     nullable=False,  unique=True),
        sa.Column("timestamp",      sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at",    sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("source",         sa.String(64),      nullable=False),
        sa.Column("event_type",     sa.String(64),      nullable=False),
        sa.Column("host",           sa.String(256),     nullable=True),
        sa.Column("user",           sa.String(256),     nullable=True),
        sa.Column("process",        sa.String(256),     nullable=True),
        sa.Column("parent_process", sa.String(256),     nullable=True),
        sa.Column("command_line",   sa.Text,            nullable=True),
        sa.Column("file_path",      sa.Text,            nullable=True),
        sa.Column("hash_md5",       sa.String(32),      nullable=True),
        sa.Column("hash_sha256",    sa.String(64),      nullable=True),
        sa.Column("src_ip",         sa.String(45),      nullable=True),
        sa.Column("dst_ip",         sa.String(45),      nullable=True),
        sa.Column("dst_port",       sa.Integer,         nullable=True),
        sa.Column("domain",         sa.String(512),     nullable=True),
        sa.Column("raw",            JSONB,              nullable=True),
    )
    op.create_index("ix_normalized_events_timestamp", "normalized_events", ["timestamp"])
    op.create_index("ix_normalized_events_source",    "normalized_events", ["source"])
    op.create_index("ix_normalized_events_event_type","normalized_events", ["event_type"])
    op.create_index("ix_normalized_events_host",      "normalized_events", ["host"])
    op.create_index("ix_normalized_events_user",      "normalized_events", ["user"])

    # ── detection_rules ───────────────────────────────────────────────────────
    op.create_table(
        "detection_rules",
        sa.Column("id",               UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("name",             sa.String(256),  nullable=False, unique=True),
        sa.Column("rule_type",        sa.String(32),   nullable=False),
        sa.Column("severity",         sa.String(16),   nullable=False),
        sa.Column("mitre_techniques", JSONB,           nullable=True),
        sa.Column("description",      sa.Text,         nullable=True),
        sa.Column("rule_content",     sa.Text,         nullable=True),
        sa.Column("enabled",          sa.Boolean,      default=True, nullable=False),
        sa.Column("created_at",       sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── incidents ─────────────────────────────────────────────────────────────
    op.create_table(
        "incidents",
        sa.Column("id",               UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("incident_id",      sa.String(64),   nullable=False, unique=True),
        sa.Column("created_at",       sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at",       sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column("title",            sa.String(512),  nullable=False),
        sa.Column("description",      sa.Text,         nullable=True),
        sa.Column("status",           sa.String(32),   default="open", nullable=False),
        sa.Column("severity",         sa.String(16),   nullable=False),
        sa.Column("risk_score",       sa.Float,        nullable=True),
        sa.Column("confidence",       sa.Float,        nullable=True),
        sa.Column("entities",         JSONB,           nullable=True),
        sa.Column("mitre_techniques", JSONB,           nullable=True),
        sa.Column("attack_story",     JSONB,           nullable=True),
        sa.Column("recommendations",  JSONB,           nullable=True),
        sa.Column("verification",     JSONB,           nullable=True),
    )
    op.create_index("ix_incidents_status",   "incidents", ["status"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])

    # ── alerts ────────────────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id",               UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("alert_id",         sa.String(64),   nullable=False, unique=True),
        sa.Column("created_at",       sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("title",            sa.String(512),  nullable=False),
        sa.Column("description",      sa.Text,         nullable=True),
        sa.Column("severity",         sa.String(16),   nullable=False),
        sa.Column("status",           sa.String(32),   default="open",  nullable=False),
        sa.Column("rule_id",          UUID(as_uuid=True), sa.ForeignKey("detection_rules.id"), nullable=True),
        sa.Column("host",             sa.String(256),  nullable=True),
        sa.Column("user",             sa.String(256),  nullable=True),
        sa.Column("mitre_techniques", JSONB,           nullable=True),
        sa.Column("threat_intel",     JSONB,           nullable=True),
        sa.Column("incident_id",      UUID(as_uuid=True), sa.ForeignKey("incidents.id"), nullable=True),
    )
    op.create_index("ix_alerts_created_at",  "alerts", ["created_at"])
    op.create_index("ix_alerts_host",        "alerts", ["host"])
    op.create_index("ix_alerts_user",        "alerts", ["user"])
    op.create_index("ix_alerts_status",      "alerts", ["status"])

    # ── alert_events (join table) ─────────────────────────────────────────────
    op.create_table(
        "alert_events",
        sa.Column("alert_id", UUID(as_uuid=True), sa.ForeignKey("alerts.id"),             primary_key=True),
        sa.Column("event_id", UUID(as_uuid=True), sa.ForeignKey("normalized_events.id"),  primary_key=True),
    )

    # ── agent_traces ──────────────────────────────────────────────────────────
    op.create_table(
        "agent_traces",
        sa.Column("id",          UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("incident_id", UUID(as_uuid=True), sa.ForeignKey("incidents.id"), nullable=True),
        sa.Column("created_at",  sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("agent_name",  sa.String(64),   nullable=False),
        sa.Column("step",        sa.Integer,      nullable=False),
        sa.Column("action",      sa.String(128),  nullable=False),
        sa.Column("tool_name",   sa.String(128),  nullable=True),
        sa.Column("tool_args",   JSONB,           nullable=True),
        sa.Column("tool_result", JSONB,           nullable=True),
        sa.Column("reasoning",   sa.Text,         nullable=True),
        sa.Column("success",     sa.Boolean,      default=True, nullable=False),
        sa.Column("error",       sa.Text,         nullable=True),
        sa.Column("duration_ms", sa.Integer,      nullable=True),
    )
    op.create_index("ix_agent_traces_incident_id", "agent_traces", ["incident_id"])
    op.create_index("ix_agent_traces_agent_name",  "agent_traces", ["agent_name"])
    op.create_index("ix_agent_traces_created_at",  "agent_traces", ["created_at"])

    # ── rag_chunks (pgvector embeddings) ──────────────────────────────────────
    op.create_table(
        "rag_chunks",
        sa.Column("id",          UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("created_at",  sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("source",      sa.String(128),  nullable=False),
        sa.Column("doc_id",      sa.String(256),  nullable=False),
        sa.Column("chunk_index", sa.Integer,      nullable=False),
        sa.Column("content",     sa.Text,         nullable=False),
        sa.Column("metadata",    JSONB,           nullable=True),
        # embedding column is added via raw SQL because Alembic doesn't natively support pgvector
    )
    op.execute("ALTER TABLE rag_chunks ADD COLUMN IF NOT EXISTS embedding vector(384)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_rag_chunks_embedding ON rag_chunks USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)")
    op.create_index("ix_rag_chunks_source",  "rag_chunks", ["source"])
    op.create_index("ix_rag_chunks_doc_id",  "rag_chunks", ["doc_id"])


def downgrade() -> None:
    """Drop all AegisX tables (reverses upgrade)."""
    op.drop_table("rag_chunks")
    op.drop_table("agent_traces")
    op.drop_table("alert_events")
    op.drop_table("alerts")
    op.drop_table("incidents")
    op.drop_table("detection_rules")
    op.drop_table("normalized_events")
    # Don't drop pgvector extension — it may be shared with other apps
