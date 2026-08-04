#!/usr/bin/env bash
# Экстренное поднятие WireGuard на уже установленном сервере.
# Запуск: bash tools/fix_wg_now.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== pull кода =="
git pull origin cursor/fix-vpn-services-after-claude-3616 || true

echo "== проверка /dev/net/tun =="
if [[ ! -e /dev/net/tun ]]; then
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200
  chmod 666 /dev/net/tun
  echo "создал /dev/net/tun"
else
  ls -la /dev/net/tun
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "== останавливаю старый wg_server =="
docker rm -f wg_server 2>/dev/null || true

CONF="data/wireguard/wg_confs/wg0.conf"
if [[ ! -f "${CONF}" ]]; then
  echo "Нет ${CONF} — сначала нажмите «Настроить» в панели WireGuard (или создайте сервер заново)."
  echo "Перед этим: bash install.sh"
  exit 1
fi

WG_PORT="$(awk -F'= *' '/^ListenPort/{print $2; exit}' "${CONF}" | tr -d '[:space:]')"
WG_PORT="${WG_PORT:-51820}"
# Address = 10.66.0.1/24 → subnet 10.66.0.0/24
WG_ADDR="$(awk -F'= *' '/^Address/{print $2; exit}' "${CONF}" | tr -d '[:space:]')"
WG_SUBNET="$(python3 - <<PY
addr = "${WG_ADDR}" or "10.66.0.1/24"
ip, _, pref = addr.partition("/")
parts = ip.split(".")
pref = pref or "24"
print(".".join(parts[:3] + ["0"]) + "/" + pref)
PY
)"

echo "== conf: port=${WG_PORT} subnet=${WG_SUBNET} =="
grep -E '^(Address|ListenPort|PostUp|PostDown)' "${CONF}" || true

echo "== запускаю контейнер с /dev/net/tun =="
docker pull lscr.io/linuxserver/wireguard:latest
docker run -d \
  --name wg_server \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  --sysctl net.ipv4.ip_forward=1 \
  -e PUID=0 -e PGID=0 \
  -p "${WG_PORT}:${WG_PORT}/udp" \
  -v "$(pwd)/data/wireguard:/config" \
  lscr.io/linuxserver/wireguard:latest

echo "== жду 10с и форсирую wg-quick up =="
sleep 10
docker exec wg_server bash -c "
  test -e /dev/net/tun || (mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 666 /dev/net/tun)
  wg-quick down /config/wg_confs/wg0.conf 2>/dev/null || true
  wg-quick up /config/wg_confs/wg0.conf
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  iptables -P FORWARD ACCEPT
  iptables -t nat -C POSTROUTING -s ${WG_SUBNET} -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s ${WG_SUBNET} -j MASQUERADE
  wg show
"

echo
echo "OK. Дальше: bash install.sh  (чтобы панель подхватила контейнер),"
echo "в UI добавь peer заново, на телефоне импортируй НОВЫЙ QR."
echo "VLESS: docker logs xray_server --tail 30"
