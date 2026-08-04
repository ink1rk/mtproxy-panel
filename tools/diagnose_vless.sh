#!/usr/bin/env bash
set -uo pipefail
CAPTURE_WINDOW_SECONDS="${1:-40}"

echo "=== xray status ==="
systemctl is-active xray || true
ss -tlnp | grep -E ':8443\b' || true

echo "=== config.json (key fields) ==="
grep -E 'minClientVer|dest|flow|serverNames|"port"|"id"' /usr/local/etc/xray/config.json 2>&1 | head -60

echo "=== journal (last ${CAPTURE_WINDOW_SECONDS}s) — подключитесь с телефона сейчас ==="
journalctl -u xray --since "${CAPTURE_WINDOW_SECONDS} seconds ago" --no-pager 2>&1 || true
echo "=== tail ==="
journalctl -u xray -n 40 --no-pager 2>&1 || true
