-- AegisX PostgreSQL Database Schema
-- Run with: psql -U aegisx_user -d aegisx -f 001_initial.sql

-- Enable pgvector for RAG embeddings
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Normalized Events ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS normalized_events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id        VARCHAR(128) UNIQUE NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ DEFAULT NOW(),
    source          VARCHAR(64) NOT NULL,
    event_type      VARCHAR(64) NOT NULL,
    host            VARCHAR(256),
    "user"          VARCHAR(256),
    process         VARCHAR(256),
    parent_process  VARCHAR(256),
    command_line    TEXT,
    file_path       TEXT,
    hash_md5        VARCHAR(32),
    hash_sha256     VARCHAR(64),
    src_ip          VARCHAR(45),
    dst_ip          VARCHAR(45),
    dst_port        INTEGER,
    domain          VARCHAR(512),
    raw             JSONB
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON normalized_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source    ON normalized_events(source);
CREATE INDEX IF NOT EXISTS idx_events_host      ON normalized_events(host);
CREATE INDEX IF NOT EXISTS idx_events_user      ON normalized_events("user");
CREATE INDEX IF NOT EXISTS idx_events_type      ON normalized_events(event_type);

-- ─── Detection Rules ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS detection_rules (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name             VARCHAR(256) UNIQUE NOT NULL,
    rule_type        VARCHAR(32) NOT NULL,       -- sigma|yara|behavioral|ioc
    severity         VARCHAR(16) NOT NULL,
    mitre_techniques JSONB,
    description      TEXT,
    rule_content     TEXT,
    enabled          BOOLEAN DEFAULT TRUE,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Incidents ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id         VARCHAR(64) UNIQUE NOT NULL,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    title               VARCHAR(512) NOT NULL,
    description         TEXT,
    status              VARCHAR(32) DEFAULT 'open',
    severity            VARCHAR(16) DEFAULT 'medium',
    risk_score          FLOAT,
    confidence          FLOAT,
    entities            JSONB,
    mitre_techniques    JSONB,
    attack_graph        JSONB,
    attack_story        JSONB,
    investigation_trace JSONB,
    recommendations     JSONB,
    actions             JSONB,
    verification        JSONB,
    analyst_feedback    JSONB
);

CREATE INDEX IF NOT EXISTS idx_incidents_status    ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity  ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created   ON incidents(created_at DESC);

-- ─── Alerts ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id         VARCHAR(64) UNIQUE NOT NULL,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    title            VARCHAR(512) NOT NULL,
    description      TEXT,
    severity         VARCHAR(16) NOT NULL,
    status           VARCHAR(32) DEFAULT 'open',
    rule_id          UUID REFERENCES detection_rules(id),
    host             VARCHAR(256),
    "user"           VARCHAR(256),
    mitre_techniques JSONB,
    threat_intel     JSONB,
    incident_id      UUID REFERENCES incidents(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_status      ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_host        ON alerts(host);
CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts(incident_id);

-- ─── Alert ↔ Event Association ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id UUID REFERENCES alerts(id) ON DELETE CASCADE,
    event_id UUID REFERENCES normalized_events(id) ON DELETE CASCADE,
    PRIMARY KEY (alert_id, event_id)
);

-- ─── Agent Audit Trail ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_traces (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    agent_name  VARCHAR(64) NOT NULL,
    step        INTEGER NOT NULL,
    action      VARCHAR(128) NOT NULL,
    tool_name   VARCHAR(128),
    tool_args   JSONB,
    tool_result JSONB,
    reasoning   TEXT,
    timestamp   TIMESTAMPTZ DEFAULT NOW(),
    duration_ms INTEGER,
    success     BOOLEAN DEFAULT TRUE,
    error       TEXT
);

CREATE INDEX IF NOT EXISTS idx_traces_incident ON agent_traces(incident_id);
CREATE INDEX IF NOT EXISTS idx_traces_agent    ON agent_traces(agent_name);

-- ─── RAG Knowledge Chunks (Phase 5) ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS knowledge_chunks (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source      VARCHAR(128),               -- mitre | sigma | playbook | cve | report
    source_id   VARCHAR(256),               -- original doc ID
    content     TEXT NOT NULL,
    embedding   vector(384),                -- sentence-transformers all-MiniLM-L6-v2
    metadata    JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chunks_source ON knowledge_chunks(source);
-- Vector index created after data load:
-- CREATE INDEX knowledge_chunks_embedding_idx ON knowledge_chunks
--   USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- ─── Analyst Feedback ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analyst_feedback (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id       UUID REFERENCES incidents(id),
    ai_classification VARCHAR(32),
    analyst_decision  VARCHAR(32),
    correct           BOOLEAN,
    notes             TEXT,
    created_at        TIMESTAMPTZ DEFAULT NOW()
);
