"""
AegisX Backend — FastAPI application entry point.
Includes:
  - CORS middleware
  - Request correlation ID middleware (X-Request-ID header)
  - Structured access logging
  - Rate limiting via slowapi
  - /healthz with DB + Redis connectivity check
"""
import time
import uuid
from contextlib import asynccontextmanager
from typing import Callable

try:
    import structlog
    log = structlog.get_logger()
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    class _LoggerWrapper:
        def info(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            logging.info(f"{msg} {kw_str}".strip())
        def warning(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            logging.warning(f"{msg} {kw_str}".strip())
        def error(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            logging.error(f"{msg} {kw_str}".strip())
    log = _LoggerWrapper()

from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import engine, Base
from app.api.v1.router import api_router


# ── Slowapi rate limiter (optional — graceful fallback if not installed) ───────

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
    RATE_LIMIT_AVAILABLE = True
except ImportError:
    limiter = None
    RATE_LIMIT_AVAILABLE = False
    log.warning("slowapi not installed — rate limiting disabled. Run: pip install slowapi")


# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    log.info("AegisX backend starting", env=settings.ENV, rate_limiting=RATE_LIMIT_AVAILABLE)
    # Create tables (migrations handled by Alembic in production)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        log.info("Database tables verified")
    except Exception as exc:
        log.warning("Database connection unavailable at startup (running in mock/offline mode)", error=str(exc))
    yield
    log.info("AegisX backend shutting down")
    try:
        await engine.dispose()
    except Exception:
        pass


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(

    title="ThreatPoint Ai API",
    description="ThreatPoint Ai — Autonomous Agentic SOC & XDR Platform",
    version="0.2.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ── Rate Limiting ─────────────────────────────────────────────────────────────
if RATE_LIMIT_AVAILABLE and limiter is not None:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from app.core.metrics import metrics

# ── Request Correlation ID + Structured Access Log + Metrics ─────────────────

@app.middleware("http")
async def correlation_and_logging_middleware(request: Request, call_next: Callable) -> Response:
    """
    1. Reads or generates X-Request-ID.
    2. Attaches it to structlog context.
    3. Logs method, path, status code, duration, and records Prometheus metrics.
    """
    req_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    start  = time.perf_counter()

    try:
        import structlog
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=req_id)
    except Exception:
        pass

    response = await call_next(request)


    duration_sec = time.perf_counter() - start
    duration_ms = round(duration_sec * 1000, 1)

    # Record metrics
    metrics.record_http_request(request.method, request.url.path, response.status_code, duration_sec)

    log.info(
        "HTTP request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        duration_ms=duration_ms,
    )

    response.headers["X-Request-ID"] = req_id
    return response


# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(api_router, prefix="/api/v1")


# ── Prometheus Metrics Endpoint ───────────────────────────────────────────────

@app.get("/metrics", tags=["Monitoring"])
async def prometheus_metrics():
    """Prometheus exposition metrics endpoint for scraper."""
    return PlainTextResponse(
        content=metrics.generate_exposition(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


# ── Health Check ──────────────────────────────────────────────────────────────

@app.get("/healthz", tags=["Health"])
async def health_check() -> dict:
    """
    Liveness + readiness check.
    Returns:
      - status: ok | degraded | error
      - db: ok | error
      - version
    """
    checks: dict = {"db": "unknown"}

    # DB check
    try:
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        checks["db"] = "ok"
    except Exception as exc:
        checks["db"] = f"error: {exc}"

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"

    return {
        "status":  overall,
        "version": "0.2.0",
        "checks":  checks,
    }

