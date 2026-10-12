#!/usr/bin/env bash
# One-time enrollment of this machine as an AegisX endpoint agent (Linux / macOS).
#
# Usage:
#   ./scripts/enroll.sh --token "<ENROLLMENT-TOKEN>" [--server https://host:8008] [--insecure]
#
#   --insecure   accept a self-signed server certificate (demo/lab only)
set -euo pipefail

AGENT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$AGENT_ROOT/config/agent.yaml"
TOKEN=""
SERVER=""
INSECURE=0
PYTHON="${PYTHON:-python3}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token)    TOKEN="$2"; shift 2 ;;
    --server)   SERVER="$2"; shift 2 ;;
    --config)   CONFIG="$2"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    -h|--help)  sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$TOKEN" ]]; then
  echo "ERROR: --token is required" >&2
  exit 2
fi

VENV="$AGENT_ROOT/.venv"
if [[ ! -d "$VENV" ]]; then
  echo "Creating virtual environment at $VENV ..."
  "$PYTHON" -m venv "$VENV"
fi
VENV_PY="$VENV/bin/python"

echo "Installing agent and dependencies ..."
"$VENV_PY" -m pip install --upgrade pip >/dev/null
"$VENV_PY" -m pip install -e "$AGENT_ROOT" >/dev/null

ARGS=(--enroll --token "$TOKEN")
[[ -f "$CONFIG" ]] && ARGS+=(--config "$CONFIG")
[[ -n "$SERVER" ]] && ARGS+=(--server "$SERVER")
[[ "$INSECURE" -eq 1 ]] && export AEGISX_AGENT_VERIFY_TLS=false

echo "Enrolling with AegisX server ..."
"$VENV_PY" -m aegisx_agent "${ARGS[@]}"

echo "Enrollment complete. Current state:"
"$VENV_PY" -m aegisx_agent --status ${CONFIG:+--config "$CONFIG"}
