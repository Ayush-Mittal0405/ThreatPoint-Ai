#!/usr/bin/env bash
# Install the AegisX agent as a launchd daemon that starts on boot (macOS).
#
# Enroll first:  ./scripts/enroll.sh --token "<TOKEN>"
# Then:          sudo ./scripts/install-launchd.sh
# Remove with:   sudo ./scripts/install-launchd.sh --uninstall
#
# Installed as a LaunchDaemon (system-wide, runs at boot before login).
# NOTE: macOS may require granting the Python binary Full Disk Access under
# System Settings -> Privacy & Security for some telemetry.
set -euo pipefail

LABEL="com.aegisx.agent"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
AGENT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$AGENT_ROOT/config/agent.yaml"

if [[ "${1:-}" == "--uninstall" ]]; then
  launchctl bootout system "$PLIST" 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  echo "Removed $LABEL."
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

VENV_PY="$AGENT_ROOT/.venv/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
  echo "Virtualenv missing. Run ./scripts/enroll.sh first." >&2
  exit 1
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "Config not found at $CONFIG — create it before installing." >&2
  exit 1
fi

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>            <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${VENV_PY}</string>
        <string>-m</string>
        <string>aegisx_agent</string>
        <string>--config</string>
        <string>${CONFIG}</string>
    </array>
    <key>WorkingDirectory</key> <string>${AGENT_ROOT}</string>
    <key>RunAtLoad</key>        <true/>
    <key>KeepAlive</key>        <true/>
    <key>StandardOutPath</key>  <string>/var/log/aegisx-agent.out.log</string>
    <key>StandardErrorPath</key><string>/var/log/aegisx-agent.err.log</string>
</dict>
</plist>
EOF

chown root:wheel "$PLIST"
chmod 644 "$PLIST"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
echo "Installed and started $LABEL."
echo "  status: sudo launchctl print system/${LABEL} | head -20"
echo "  logs:   tail -f /var/log/aegisx-agent.out.log"
