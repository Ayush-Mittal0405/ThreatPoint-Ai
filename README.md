# ThreatPoint Ai — Agentic AI Autonomous SOC & XDR Platform

> **From Alerts to Attack Stories, From Investigation to Verified Response.**

ThreatPoint Ai is a modular, AI-native Security Operations Center (SOC) and Extended Detection and Response (XDR) platform that combines deterministic behavioral detection, multi-agent AI reasoning loops, live threat intelligence, pgvector RAG, NetworkX knowledge graph mapping, and human-in-the-loop remediation to autonomously investigate security incidents.

---

## Architecture Pipeline

```
Multi-Source Telemetry (Windows, Linux, Zeek, Okta, CloudTrail)
                          ↓
        Normalization & Deduplication (SHA256 event ID)
                          ↓
     Behavioral Detection Engine (5 built-in SIGMA/MITRE rules)
                          ↓
   Temporal & Entity Correlation Engine (30-min window clusters)
                          ↓
                   Security Incident
                          ↓
                  AI Triage Agent (P1-P4 priority & severity)
                          ↓
             AI Investigation Agent (ReAct reasoning loop)
                 ├── Search Tools (endpoint, process trees, network)
                 ├── Threat Intel (VirusTotal, AbuseIPDB, AlienVault OTX)
                 ├── Semantic RAG (sentence-transformers + pgvector)
                 └── Knowledge Graph (NetworkX entity relationships)
                          ↓
      Attack Story Reconstruction & 7-Factor Risk Scoring (0-100)
                          ↓
           Response Agent (Prioritized containment recommendations)
                          ↓
                 [ Human Approval Gate ] (Mandatory)
                          ↓
             Response Execution (Lab-safe reversible actions)
                          ↓
            Verification Agent (Post-remediation telemetry checks)
                          ↓
         Continuous Learning & Fine-Tuning (Analyst reviews → QLoRA)
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend API** | Python 3.11, FastAPI, Pydantic v2, SQLAlchemy (Async), Alembic |
| **Task Queue & Cache** | Redis 7, ARQ async worker queue |
| **Vector Database** | PostgreSQL 16 + pgvector |
| **LLM Inference** | Ollama (Llama-3.2, Mistral, Qwen) / OpenAI-compatible / Fallback heuristics |
| **Machine Learning** | QLoRA via HuggingFace PEFT + BitsAndBytes + TRL (4-bit NF4) |
| **Knowledge Graph** | NetworkX entity-relationship graph mapping |
| **Threat Intelligence** | VirusTotal API, AbuseIPDB API, AlienVault OTX |
| **Frontend** | React 18, TypeScript, Vite, Recharts, Lucide Icons |
| **Telemetry Collectors** | Windows (EventLog/Sysmon), Linux (auth.log/proc), Zeek, Okta, AWS CloudTrail |
| **Deployment** | Docker, Docker Compose, Nginx Multi-Stage, GitHub Actions CI |

---

## Quick Start

### 1. Clone and configure
```bash
git clone <repo>
cd ThreatPoint Ai
cp .env.example .env
# Edit .env and configure keys/tokens if using live external services
```

### 2. Start PostgreSQL (pgvector) & Redis
```bash
docker-compose up -d postgres redis
```

### 3. Run Backend API & Background Worker
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
*In a separate terminal to run background AI tasks:*
```bash
cd backend
arq app.worker.WorkerSettings
```

### 4. Run Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```
Navigate to `http://localhost:5173` (or `http://localhost:3000`).

### 5. API Documentation & Interactive Swagger
Open `http://localhost:8000/docs` or `http://localhost:8000/api/docs`.

---

## Development Phases & Roadmap

| Phase | Module | Description | Status |
|---|---|---|---|
| **0** | Architecture + Scaffold | Directory scaffolding, Pydantic v2 schemas, DB models, config | ✅ Complete |
| **1** | Multi-Source Telemetry | Normalization, Windows, Linux, Zeek, Okta, CloudTrail collectors | ✅ Complete |
| **2** | Detection Engine | Behavioral & MITRE rule engine with Sigma-style signatures | ✅ Complete |
| **3** | Alert Correlation | Temporal 30-min window & host/user entity clustering into Incidents | ✅ Complete |
| **4** | Agentic Investigation | ReAct Investigation Agent loop with read-only tools & trace auditing | ✅ Complete |
| **5** | RAG & Threat Intel | 384-dim embedder, pgvector retriever, VT/AbuseIPDB/OTX lookups | ✅ Complete |
| **6** | Knowledge Graph & Story | NetworkX process graph, MITRE kill-chain narrative generator | ✅ Complete |
| **7** | Threat Hunting | Hunting Agent with heuristic & LLM hypothesis testing loops | ✅ Complete |
| **8** | Response & Verification | Lab-safe containment actions, human approval gate, verification loop | ✅ Complete |
| **9** | ML Fine-Tuning Pipeline | ChatML dataset builder, 4-bit QLoRA trainer, Ollama Modelfile export | ✅ Complete |
| **10** | Continuous Learning & UI | Analyst feedback reviews, universal command palette (`Ctrl+K`), PDF report export | ✅ Complete |

---

## Key Features

### 🔍 Command Palette & Dark SOC Interface
- Universal search dialog (`Ctrl+K` / `Cmd+K`) searching across Incidents, Alerts, Threat Hunts, and Pages.
- Live background alert polling with real-time toast notifications for critical and high severity threats.
- Interactive MITRE ATT&CK Attack Story visualizer with NetworkX graph representation.

### 🤖 Autonomous Agent Loops
- **Triage Agent**: Classifies alert severity and recommends immediate investigation priorities.
- **Investigation Agent**: Queries endpoint processes, network streams, and external intelligence with automated step auditing to `AgentTrace`.
- **Response Agent**: Recommends isolation, IP blocking, or account locking, strictly enforcing human approval.
- **Verification Agent**: Validates remediation success through telemetry re-checks.

### 🧠 Fine-Tuning & Evaluation Suite
- **Dataset Builder (`ml/datasets/dataset_builder.py`)**: Generates instruction-tuning datasets in ChatML / Alpaca formats with train/val/test splits.
- **QLoRA Trainer (`ml/training/finetune.py`)**: 4-bit quantized adapter fine-tuning with instant Ollama Modelfile export.
- **Security Benchmark (`ml/evaluation/evaluate.py`)**: Automated scoring of Precision, Recall, F1, and Hallucination rate feeding the live `Models.tsx` dashboard.

### 📄 Executive Incident Reporting
- Direct download of Executive Markdown Reports (`.md`) and printable HTML/PDF dossiers via `/api/v1/incidents/{id}/export/markdown` and `/export/html`.

---

## Security Principles

1. **Evidence over assumptions**: Every AI claim requires correlated telemetry artifact IDs.
2. **Deterministic controls**: Risk scores (0-100) are computed mathematically via `RiskEngine`, not free-form text.
3. **Mandatory Human-in-the-Loop**: All destructive response tools enforce `requires_human_approval = True`.
4. **Least privilege**: Investigation agents have read-only access to query telemetry.
5. **No hard-coded secrets**: All credentials and API keys are loaded via environment variables.

---

## License & Disclaimer

Research and educational use only. All active testing must be performed only on systems explicitly authorized for security evaluations.
