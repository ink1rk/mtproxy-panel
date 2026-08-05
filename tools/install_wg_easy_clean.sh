#!/usr/bin/env bash
# Чистая установка официального wg-easy v14 на пустой Ubuntu/Debian.
# Никакой панели, никакого native wg-quick — только wg-easy.
#
# Usage (под root):
#   curl -fsSL ... | bash
#   или: bash tools/install_wg_easy_clean.sh
set -euo pipefail

WG_HOST_IP="${WG_HOST_IP:-$(curl -4 -fsS https://api.ipify.org)}"
PASSWORD="${WG_EASY_PASSWORD:-mtproxy-wg}"
DATA_DIR="${WG_EASY_DIR:-/root/wg-easy}"
WG_PORT="${WG_PORT:-51820}"
UI_PORT="${UI_PORT:-51821}"

export DEBIAN_FRONTEND=noninteractive

echo "== 1. packages =="
apt-get update -y
apt-get install -y curl ca-certificates gnupg iptables

if ! command -v docker >/dev/null 2>&1; then
  echo "== 2. install Docker =="
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
else
  echo "== 2. Docker already present =="
  systemctl enable --now docker
fi

# iptables-nft предпочтительнее на новых Ubuntu; Docker так же дружит с nft
update-alternatives --set iptables /usr/sbin/iptables-nft 2>/dev/null || true
update-alternatives --set ip6tables /usr/sbin/ip6tables-nft 2>/dev/null || true
systemctl restart docker || true

echo "== 3. cleanup old WG =="
docker rm -f wg-easy wg_server 2>/dev/null || true
systemctl disable --now wg-quick@wg0 2>/dev/null || true
wg-quick down wg0 2>/dev/null || true
ip link delete wg0 2>/dev/null || true
rm -rf "${DATA_DIR}"
mkdir -p "${DATA_DIR}"

echo "== 4. sysctl =="
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null || true
cat >/etc/sysctl.d/99-wireguard-forward.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.src_valid_mark=1
EOF

echo "== 5. password hash =="
docker pull ghcr.io/wg-easy/wg-easy:14
HASH="$(docker run --rm ghcr.io/wg-easy/wg-easy:14 wgpw "${PASSWORD}" \
  | sed -n "s/.*PASSWORD_HASH='\\(.*\\)'/\\1/p")"
if [[ -z "${HASH}" ]]; then
  echo "Не удалось получить PASSWORD_HASH" >&2
  exit 1
fi

echo "== 6. run wg-easy (host network, как на рабочем VPS) =="
# host network: без docker-proxy UDP (на Timeweb bridge/DNAT часто ломается)
docker run -d \
  --name=wg-easy \
  --network host \
  -e LANG=en \
  -e "WG_HOST=${WG_HOST_IP}" \
  -e "PASSWORD_HASH=${HASH}" \
  -e "PORT=${UI_PORT}" \
  -e "WG_PORT=${WG_PORT}" \
  -e WG_DEFAULT_ADDRESS=10.8.0.x \
  -e WG_DEFAULT_DNS=1.1.1.1 \
  -e WG_MTU=1280 \
  -e WG_PERSISTENT_KEEPALIVE=25 \
  -e WG_ALLOWED_IPS=0.0.0.0/0 \
  -e WG_DEVICE=eth0 \
  -v "${DATA_DIR}:/etc/wireguard" \
  -v /lib/modules:/lib/modules:ro \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  --device /dev/net/tun:/dev/net/tun \
  --restart unless-stopped \
  ghcr.io/wg-easy/wg-easy:14

iptables -P FORWARD ACCEPT 2>/dev/null || true
sleep 3

echo "== 7. status =="
docker ps --filter name=wg-easy
docker exec wg-easy wg show || wg show || true
ss -ulnp | grep -E ":${WG_PORT}\\b" || true
ss -tlnp | grep -E ":${UI_PORT}\\b" || true

echo
echo "============================================"
echo "wg-easy готов (чистая установка)"
echo "  UI:       http://${WG_HOST_IP}:${UI_PORT}"
echo "  Password: ${PASSWORD}"
echo "  WG UDP:   ${WG_HOST_IP}:${WG_PORT}"
echo
echo "В UI: New Client → QR → импорт в WireGuard."
echo "Timeweb Firewall (если включён): UDP ${WG_PORT} + TCP ${UI_PORT}."
echo "Закрытые 25/587/3389/... к WG не относятся."
echo "============================================"
