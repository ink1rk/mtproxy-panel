#!/usr/bin/env bash
set -uo pipefail
WG_PORT="${WG_PORT:-51820}"
VLESS_PORT="${VLESS_PORT:-8443}"

echo "=== 1. Сервисы ==="
systemctl is-active mtproxy-panel 2>/dev/null || true
docker ps --filter name=wg_server --format '{{.Names}} {{.Status}} {{.Ports}}' || echo "wg_server missing"
systemctl is-active xray 2>/dev/null || echo "xray: inactive"

echo
echo "=== 2. Native wg-quick должен быть ВЫКЛ ==="
systemctl is-active wg-quick@wg0 2>/dev/null || echo "wg-quick@wg0: inactive (OK)"

echo
echo "=== 3. Публичный IP ==="
curl -4 -fsS --max-time 5 https://api.ipify.org && echo || echo "(fail)"

echo
echo "=== 4. Порты ==="
ss -ulnp | grep -E ":${WG_PORT}\\b" || echo "UDP ${WG_PORT}: НЕ слушается"
ss -tlnp | grep -E ":${VLESS_PORT}\\b" || echo "TCP ${VLESS_PORT}: НЕ слушается"

echo
echo "=== 5. WireGuard inside Docker (wg-easy style) ==="
if docker ps --format '{{.Names}}' | grep -qx wg_server; then
  docker exec wg_server wg show || true
  echo "--- PostUp / conf ---"
  docker exec wg_server grep -E '^(Address|ListenPort|MTU|PostUp|PostDown)' /config/wg_confs/wg0.conf || true
  echo "--- NAT inside container ---"
  docker exec wg_server iptables -t nat -S POSTROUTING || true
  docker exec wg_server iptables -S FORWARD | head -10 || true
else
  echo "wg_server не запущен"
fi

echo
echo "=== 6. Xray ==="
systemctl is-active xray 2>/dev/null || echo "inactive"

echo
echo "=== 7. iPhone ==="
echo "Новый QR из панели. AllowedIPs=0.0.0.0/0"
echo "После серфинга: docker exec wg_server wg show  — transfer в KB/MB"
