#!/bin/bash
# Stop the Relay service and remove it from launchd. Saved devices and proxies stay in data/.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi
LABEL="local.relay.gateway"
launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist"
# The service removes its pf rules on shutdown; flush again in case it was killed.
/sbin/pfctl -a com.apple/relay -F all 2>/dev/null || true
echo "Relay service removed."
