"""
AegisX agent command-line entry point.

Usage:
    python -m aegisx_agent --config config/agent.yaml
    python -m aegisx_agent --enroll --config config/agent.yaml   # enroll then exit
    python -m aegisx_agent --status --config config/agent.yaml    # print state and exit
"""
from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path

from .agent import AgentRunner
from .config import Config
from .enrollment import ensure_enrolled
from .logging_setup import setup_logging
from .state import StateStore
from .transport import Transport


def _load_config(args) -> Config:
    cfg = Config.load(args.config) if args.config else Config.load(None)
    if args.server:
        cfg.server.url = args.server
    if args.token:
        cfg.enrollment_token = args.token
    cfg.validate()
    return cfg


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="aegisx-agent", description="AegisX endpoint agent")
    parser.add_argument("--config", help="Path to agent YAML config")
    parser.add_argument("--server", help="Override server URL")
    parser.add_argument("--token", help="Enrollment token (one-time)")
    parser.add_argument("--enroll", action="store_true", help="Enroll then exit")
    parser.add_argument("--status", action="store_true", help="Print agent state then exit")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    try:
        config = _load_config(args)
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    log = setup_logging(config.state_dir, args.log_level)

    if args.status:
        state = StateStore(config.state_dir).load()
        print(f"enrolled:   {state.enrolled}")
        print(f"agent_id:   {state.agent_id}")
        print(f"server_url: {state.server_url}")
        print(f"enrolled_at:{state.enrolled_at}")
        print("(agent credential present)" if state.agent_token else "(no credential)")
        return 0

    if args.enroll:
        transport = Transport(config, log)
        try:
            creds = ensure_enrolled(config, StateStore(config.state_dir), transport, log)
        except Exception as exc:
            log.error("Enrollment failed: %s", exc)
            return 1
        log.info("Enrolled successfully as %s", creds.agent_id)
        return 0

    runner = AgentRunner(config, log)

    def _handle_signal(signum, _frame):
        log.info("Received signal %s", signum)
        runner.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle_signal)
        except (ValueError, OSError):  # not in main thread / unsupported
            pass

    try:
        runner.run()
    except KeyboardInterrupt:
        runner.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
