"""
AegisX API v1 — main router.
"""
from fastapi import APIRouter

from app.api.v1.endpoints import (
    telemetry, alerts, incidents, agents,
    rag, attack_story, response, hunting, metrics, feedback, export, fleet,
    endpoint_agents,
)

api_router = APIRouter()

api_router.include_router(telemetry.router,     prefix="/telemetry",     tags=["Telemetry"])
api_router.include_router(alerts.router,         prefix="/alerts",        tags=["Alerts"])
api_router.include_router(incidents.router,      prefix="/incidents",     tags=["Incidents"])
api_router.include_router(agents.router,         prefix="/agents",        tags=["Agents"])
api_router.include_router(rag.router,            prefix="/rag",           tags=["RAG"])
api_router.include_router(attack_story.router,   prefix="/attack-story",  tags=["Attack Story"])
api_router.include_router(response.router,       prefix="/response",      tags=["Response"])
api_router.include_router(hunting.router,        prefix="/hunting",       tags=["Hunting"])
api_router.include_router(metrics.router,        prefix="/models",        tags=["Model Metrics"])
api_router.include_router(feedback.router,       prefix="/feedback",      tags=["Analyst Feedback"])
api_router.include_router(export.router,         prefix="/export",        tags=["Export"])
api_router.include_router(export.router,         prefix="/incidents",     tags=["Export"])
api_router.include_router(fleet.router,          prefix="/fleet",         tags=["Fleet Management"])
api_router.include_router(endpoint_agents.router, prefix="/endpoints",    tags=["Endpoint Agents"])




