#!/bin/bash
# Install Relay as a launchd service that starts at boot and runs as root
# (root is needed for pf rules and the sing-box redirect listener).
# Usage: sudo scripts/install.sh [path-to-node]
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

DIR="$(cd "$(dirname "$0")/.." && pwd)"
NODE="${1:-}"
if [[ -z "$NODE" ]]; then
  NODE="$(sudo -u "${SUDO_USER:-root}" bash -lc 'command -v node' 2>/dev/null || true)"
fi
SING_BOX="${RELAY_SING_BOX:-/opt/homebrew/bin/sing-box}"
LABEL="local.relay.gateway"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
PORT="${RELAY_PORT:-8787}"

[[ -x "$NODE" ]] || { echo "Node not found. Pass its path: sudo $0 /path/to/node" >&2; exit 1; }
[[ -x "$SING_BOX" ]] || { echo "sing-box not found at $SING_BOX. Install it: brew install sing-box" >&2; exit 1; }

mkdir -p "$DIR/data"
OWNER="$(stat -f '%u:%g' "$DIR")"
touch "$DIR/data/relay.log"
chown "$OWNER" "$DIR/data" "$DIR/data/relay.log"

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$NODE</string>
    <string>$DIR/server.mjs</string>
  </array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>RELAY_SING_BOX</key><string>$SING_BOX</string>
    <key>RELAY_PORT</key><string>$PORT</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ExitTimeOut</key><integer>15</integer>
  <key>StandardOutPath</key><string>$DIR/data/relay.log</string>
  <key>StandardErrorPath</key><string>$DIR/data/relay.log</string>
</dict>
</plist>
PLIST
chmod 644 "$PLIST"

launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable "system/$LABEL"

echo "Relay is running at http://localhost:$PORT. For Tailscale and phone access, see Dashboard access in README.md."
echo "Log: $DIR/data/relay.log"
