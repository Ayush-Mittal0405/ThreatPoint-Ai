#!/usr/bin/env bash
# Install the AegisX agent as a systemd service that starts on boot (Linux).
#
# Enroll first:  ./scripts/enroll.sh --token "<TOKEN>"
# Then:          sudo ./scripts/install-systemd.sh
# Remove with:   sudo ./scripts/install-systemd.sh --uninstall
#
# Runs as root because the network collector needs privileged access to the full
# socket table. Reduce to a dedicated user if you only need process telemetry.
set -euo pipefail

SERVICE_NAME="aegisx-agent"
UNIT="/etc/systemd/system/${SERVICE_NAME}.service"
AGENT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$AGENT_ROOT/config/agent.yaml"

if [[ "${1:-}" == "--uninstall" ]]; then
  systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload
  echo "Removed $SERVICE_NAME."
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "Config not found at $CONFIG — create it before installing the service." >&2
  exit 1
fi

VENV_PY="$AGENT_ROOT/.venv/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
  echo "Virtualenv missing. Run ./scripts/enroll.sh first." >&2
  exit 1
fi

cat > "$UNIT" <<EOF
[Unit]
Description=AegisX Endpoint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$VENV_PY -m aegisx_agent --config $CONFIG
WorkingDirectory=$AGENT_ROOT
Restart=always
RestartSec=10
User=root
# Hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
echo "Installed and started $SERVICE_NAME."
echo "  status: systemctl status $SERVICE_NAME"
echo "  logs:   journalctl -u $SERVICE_NAME -f"
