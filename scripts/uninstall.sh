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
# Release Relay's pf enable reference, if it was taken in this boot and pf is still on.
TOKEN_FILE="$(cd "$(dirname "$0")/.." && pwd)/data/runtime/pf-token"
if [[ -f "$TOKEN_FILE" ]]; then
  read -r TOKEN BOOT < "$TOKEN_FILE" || true
  NOW_BOOT="$(sysctl -n kern.boottime | sed -E 's/.*sec = ([0-9]+).*/\1/')"
  if [[ -n "${TOKEN:-}" && "${BOOT:-}" == "$NOW_BOOT" ]] && /sbin/pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
    /sbin/pfctl -X "$TOKEN" 2>/dev/null || true
  fi
  rm -f "$TOKEN_FILE"
fi
echo "Relay service removed."
