#!/usr/bin/env bash
#
# Быстрая проверка native VPN-стека.
# Запуск: bash tools/quick_check.sh
#
set -uo pipefail

WG_PORT="${WG_PORT:-51820}"
VLESS_PORT="${VLESS_PORT:-8443}"

echo "=== 1. Сервисы ==="
systemctl is-active mtproxy-panel 2>/dev/null || true
systemctl is-active wg-quick@wg0 2>/dev/null || echo "wg-quick@wg0: inactive"
systemctl is-active xray 2>/dev/null || echo "xray: inactive"
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null \
  | grep -E 'NAMES|mtproxy_' || true

echo
echo "=== 2. NetworkMode legacy docker (должно быть пусто) ==="
docker ps -a --format '{{.Names}} {{.HostConfig.NetworkMode}}' 2>/dev/null \
  | grep -E 'wg_server|xray_server' || echo "(legacy контейнеров нет — OK)"

echo
echo "=== 3. Публичный IP ==="
curl -4 -fsS --max-time 5 https://api.ipify.org && echo || echo "(не удалось)"

echo
echo "=== 4. Порты ==="
ss -ulnp | grep -E ":${WG_PORT}\\b" || echo "UDP ${WG_PORT}: НЕ слушается"
ss -tlnp | grep -E ":${VLESS_PORT}\\b" || echo "TCP ${VLESS_PORT}: НЕ слушается"

echo
echo "=== 5. WireGuard ==="
if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
  wg show || true
  echo "--- conf ---"
  grep -E '^(Address|ListenPort|MTU|PublicKey|AllowedIPs)' /etc/wireguard/wg0.conf 2>/dev/null | head -40 || true
else
  echo "wg-quick@wg0 не active"
fi

echo
echo "=== 6. nftables NAT ==="
nft list table inet mtproxy-panel 2>/dev/null || echo "таблицы mtproxy-panel нет"
echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '?')"
ip -4 route show default || true

echo
echo "=== 7. Xray ==="
if systemctl is-active --quiet xray 2>/dev/null; then
  grep -E 'minClientVer|dest|flow|serverNames|"port"' /usr/local/etc/xray/config.json 2>/dev/null | head -40 || true
  journalctl -u xray -n 15 --no-pager 2>/dev/null || true
else
  echo "xray не active"
fi

echo
echo "=== 8. Что сделать ==="
echo "1) Timeweb firewall: ${WG_PORT}/udp, ${VLESS_PORT}/tcp, 8000/tcp"
echo "2) Панель: сброс WG/VLESS → настроить заново → новый QR на телефоне"
echo "3) После handshake: wg show — transfer должен расти (не 1–3 KiB)"
