"""
Operational logging for the agent.

Writes rotating local logs under the state directory and mirrors to stderr.
Never logs secrets (credentials/tokens are passed as objects, not formatted).
"""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path


def setup_logging(state_dir: str, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("aegisx_agent")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    logger.addHandler(stream)

    try:
        log_dir = Path(state_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        fileh = logging.handlers.RotatingFileHandler(
            log_dir / "aegisx-agent.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8"
        )
        fileh.setFormatter(fmt)
        logger.addHandler(fileh)
    except OSError:
        logger.warning("Could not open log file; continuing with console logging only")

    logger.propagate = False
    return logger
