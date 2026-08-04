#!/usr/bin/env bash
#
# Быстрая проверка: почему телефон не ходит в интернет через WG/VLESS.
# Запуск: bash tools/quick_check.sh
#
set -uo pipefail

WG_PORT="${WG_PORT:-51820}"
VLESS_PORT="${VLESS_PORT:-8443}"

echo "=== 1. Контейнеры ==="
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E 'NAMES|wg_server|xray_server|mtproxy_' || true

echo
echo "=== 2. Публичный IP сервера (должен совпадать с Endpoint/vless:// в панели) ==="
curl -4 -fsS --max-time 5 https://api.ipify.org && echo || echo "(не удалось определить)"

echo
echo "=== 3. Слушает ли хост порты VPN ==="
ss -ulnp | grep -E ":${WG_PORT}\\b" || echo "UDP ${WG_PORT}: НЕ слушается"
ss -tlnp | grep -E ":${VLESS_PORT}\\b" || echo "TCP ${VLESS_PORT}: НЕ слушается"

echo
echo "=== 4. WireGuard inside container ==="
if docker ps --format '{{.Names}}' | grep -qx wg_server; then
  docker exec wg_server wg show || true
  echo "--- default route / NAT ---"
  docker exec wg_server ip -4 route show default || true
  docker exec wg_server iptables -t nat -S POSTROUTING || true
  echo "--- server conf PostUp ---"
  docker exec wg_server grep -E '^(Address|ListenPort|PostUp|PostDown)' /config/wg_confs/wg0.conf || true
else
  echo "wg_server не запущен"
fi

echo
echo "=== 5. Xray inside container ==="
if docker ps --format '{{.Names}}' | grep -qx xray_server; then
  docker exec xray_server sh -c 'grep -E "minClientVer|dest|flow|serverNames" -n /etc/xray/config.json | head -40' || true
  echo "--- recent logs ---"
  docker logs xray_server --tail 20 2>&1 || true
else
  echo "xray_server не запущен"
fi

echo
echo "=== 6. ufw ==="
ufw status verbose 2>/dev/null || echo "ufw нет/не активен"

echo
echo "=== 7. Что сделать руками ==="
echo "1) В панели Timeweb (Firewall / Security Group) открой:"
echo "   - ${WG_PORT}/udp  (WireGuard)"
echo "   - ${VLESS_PORT}/tcp (VLESS)"
echo "   - 8000/tcp (панель)"
echo "2) В панели: WireGuard → Перезапустить сервер; VLESS → Перезапустить сервер"
echo "3) На телефоне УДАЛИ старые профили и заново импортируй QR/.conf/vless:// из панели"
echo "4) Подключись с телефона, затем снова:"
echo "   docker exec wg_server wg show"
echo "   docker logs xray_server --tail 30"
echo "   Если у WG latest handshake = 0 / нет строк transfer — пакеты с телефона НЕ доходят (облачный firewall)."
echo "   Если handshake есть, а интернета нет — смотри NAT (PostUp) выше."
