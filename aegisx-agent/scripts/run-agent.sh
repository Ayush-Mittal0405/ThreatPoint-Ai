#!/usr/bin/env bash
# Run the AegisX endpoint agent in the foreground (Linux / macOS).
#
# Usage:
#   ./scripts/run-agent.sh [--config config/agent.yaml] [--insecure]
set -euo pipefail

AGENT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$AGENT_ROOT/config/agent.yaml"
INSECURE=0
PYTHON="${PYTHON:-python3}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)   CONFIG="$2"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    -h|--help)  sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

VENV="$AGENT_ROOT/.venv"
if [[ ! -d "$VENV" ]]; then
  "$PYTHON" -m venv "$VENV"
fi
VENV_PY="$VENV/bin/python"
"$VENV_PY" -m pip install --upgrade pip >/dev/null
"$VENV_PY" -m pip install -e "$AGENT_ROOT" >/dev/null

if [[ ! -f "$CONFIG" ]]; then
  echo "Config not found at $CONFIG" >&2
  echo "Copy config/agent.example.yaml to config/agent.yaml and set server.url" >&2
  exit 1
fi

[[ "$INSECURE" -eq 1 ]] && export AEGISX_AGENT_VERIFY_TLS=false

echo "Starting AegisX agent (Ctrl+C to stop) ..."
exec "$VENV_PY" -m aegisx_agent --config "$CONFIG"
