#!/usr/bin/env bash
# Drive a REAL Chrome to register a malicious service worker that stages a
# cross-origin payload in Cache Storage, then run FLOTSAM on the real on-disk
# profile. Proves the whole pipeline against genuine browser artifacts.
#
# Usage: scripts/real_capture.sh [chrome_binary]
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CHROME="${1:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
PROFILE="$(mktemp -d /tmp/flotsam_chrome.XXXXXX)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

echo "[*] serving victim :8000 and attacker :8001"
python3 -m http.server 8000 --directory "$REPO/demo/victim" >/dev/null 2>&1 & PIDS+=($!)
python3 "$REPO/scripts/attacker_server.py" 8001 "$REPO/demo/attacker" >/dev/null 2>&1 & PIDS+=($!)
sleep 1

echo "[*] launching headless Chrome with a fresh profile: $PROFILE"
"$CHROME" --headless=new --user-data-dir="$PROFILE" \
  --no-first-run --no-default-browser-check --disable-gpu \
  --disable-background-networking \
  "http://localhost:8000/" >/dev/null 2>&1 & CHROME_PID=$!
PIDS+=($CHROME_PID)

echo "[*] waiting for the service worker to install + cache the payload..."
sleep 10
echo "[*] stopping Chrome gracefully so it flushes Cache Storage + the SW DB"
kill -TERM "$CHROME_PID" 2>/dev/null || true
sleep 3

PROF="$PROFILE/Default"
echo "[*] on-disk artifacts written by Chrome:"
find "$PROF/Service Worker" -maxdepth 3 -type d 2>/dev/null | sed "s#$PROF/##" | head -20 || true

echo
echo "[*] FLOTSAM deep extraction of the REAL profile:"
PYTHONPATH="$REPO/src" python3 -m flotsam.cli inventory --deep \
  --profile "$PROF" --out "$PROFILE/real_inventory.json"
echo
echo "[*] FLOTSAM hunt:"
PYTHONPATH="$REPO/src" python3 -m flotsam.cli hunt --inventory "$PROFILE/real_inventory.json"
echo
echo "[*] inventory saved: $PROFILE/real_inventory.json"
