"""
Alembic migration: 002_endpoint_agents

Adds the real endpoint-agent integration:
  - endpoint_agents      (enrolled agents + hashed credential)
  - enrollment_tokens    (bootstrap tokens, hashed)
  - agent_heartbeats     (heartbeat history)
  - agent_security_logs  (security audit trail)

Also adds a nullable, indexed `agent_id` column to `normalized_events` and
`alerts` so endpoint telemetry and detections can be attributed to a specific
enrolled agent (distinct from hostname).

To apply:
    cd aegisx/backend
    alembic upgrade head
"""
from __future__ import annotations

import uuid
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

# ── Migration metadata ────────────────────────────────────────────────────────
revision = "002_endpoint_agents"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── attribute existing tables to an agent ─────────────────────────────────
    op.add_column("normalized_events", sa.Column("agent_id", sa.String(64), nullable=True))
    op.create_index("ix_normalized_events_agent_id", "normalized_events", ["agent_id"])
    op.add_column("alerts", sa.Column("agent_id", sa.String(64), nullable=True))
    op.create_index("ix_alerts_agent_id", "alerts", ["agent_id"])

    # ── endpoint_agents ───────────────────────────────────────────────────────
    op.create_table(
        "endpoint_agents",
        sa.Column("id",               UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("agent_id",         sa.String(64),  nullable=False, unique=True),
        sa.Column("token_hash",       sa.String(64),  nullable=False),
        sa.Column("hostname",         sa.String(256), nullable=False),
        sa.Column("operating_system", sa.String(64),  nullable=True),
        sa.Column("os_version",       sa.String(128), nullable=True),
        sa.Column("agent_version",    sa.String(32),  nullable=True),
        sa.Column("username",         sa.String(128), nullable=True),
        sa.Column("ip_address",       sa.String(45),  nullable=True),
        sa.Column("mac_address",      sa.String(32),  nullable=True),
        sa.Column("status",           sa.String(32),  server_default="online"),
        sa.Column("health",           sa.String(32),  server_default="healthy"),
        sa.Column("risk_score",       sa.Integer,     server_default="0"),
        sa.Column("revoked",          sa.Boolean,     server_default=sa.false()),
        sa.Column("first_seen",       sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen",        sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("enrolled_at",      sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("labels",           JSONB, nullable=True),
    )
    op.create_index("ix_endpoint_agents_agent_id", "endpoint_agents", ["agent_id"], unique=True)
    op.create_index("ix_endpoint_agents_hostname", "endpoint_agents", ["hostname"])
    op.create_index("ix_endpoint_agents_last_seen", "endpoint_agents", ["last_seen"])

    # ── enrollment_tokens ─────────────────────────────────────────────────────
    op.create_table(
        "enrollment_tokens",
        sa.Column("id",         UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("token_hash", sa.String(64),  nullable=False, unique=True),
        sa.Column("label",      sa.String(128), nullable=True),
        sa.Column("max_uses",   sa.Integer,     server_default="1"),
        sa.Column("used_count", sa.Integer,     server_default="0"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("revoked",    sa.Boolean,     server_default=sa.false()),
    )
    op.create_index("ix_enrollment_tokens_token_hash", "enrollment_tokens", ["token_hash"], unique=True)

    # ── agent_heartbeats ──────────────────────────────────────────────────────
    op.create_table(
        "agent_heartbeats",
        sa.Column("id",               UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("agent_id",         sa.String(64), nullable=False),
        sa.Column("received_at",      sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("agent_version",    sa.String(32),  nullable=True),
        sa.Column("status",           sa.String(32),  nullable=True),
        sa.Column("cpu_usage_pct",    sa.Float,       nullable=True),
        sa.Column("memory_usage_pct", sa.Float,       nullable=True),
        sa.Column("queued_events",    sa.Integer,     nullable=True),
    )
    op.create_index("ix_agent_heartbeats_agent_id", "agent_heartbeats", ["agent_id"])
    op.create_index("ix_agent_heartbeats_received_at", "agent_heartbeats", ["received_at"])

    # ── agent_security_logs ───────────────────────────────────────────────────
    op.create_table(
        "agent_security_logs",
        sa.Column("id",        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("agent_id",  sa.String(64),  nullable=True),
        sa.Column("event",     sa.String(64),  nullable=False),
        sa.Column("source_ip", sa.String(45),  nullable=True),
        sa.Column("detail",    sa.Text,        nullable=True),
        sa.Column("success",   sa.Boolean,     server_default=sa.true()),
    )
    op.create_index("ix_agent_security_logs_agent_id", "agent_security_logs", ["agent_id"])
    op.create_index("ix_agent_security_logs_timestamp", "agent_security_logs", ["timestamp"])


def downgrade() -> None:
    op.drop_table("agent_security_logs")
    op.drop_table("agent_heartbeats")
    op.drop_table("enrollment_tokens")
    op.drop_table("endpoint_agents")
    op.drop_index("ix_alerts_agent_id", table_name="alerts")
    op.drop_column("alerts", "agent_id")
    op.drop_index("ix_normalized_events_agent_id", table_name="normalized_events")
    op.drop_column("normalized_events", "agent_id")
