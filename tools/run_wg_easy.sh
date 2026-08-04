#!/usr/bin/env bash
# Официальный wg-easy (проверено на ams-1-vm-8cfh: SELFTEST ping 1.1.1.1 OK).
# UI: http://<IP>:51821  пароль по умолчанию: mtproxy-wg
set -euo pipefail

WG_HOST_IP="${WG_HOST_IP:-$(curl -4 -fsS https://api.ipify.org)}"
PASSWORD="${WG_EASY_PASSWORD:-mtproxy-wg}"
DATA_DIR="${WG_EASY_DIR:-/root/wg-easy}"

systemctl disable --now wg-quick@wg0 2>/dev/null || true
wg-quick down wg0 2>/dev/null || true
ip link delete wg0 2>/dev/null || true
docker rm -f wg_server wg-easy 2>/dev/null || true

modprobe iptable_nat iptable_filter 2>/dev/null || true
mkdir -p "${DATA_DIR}"

HASH="$(docker run --rm ghcr.io/wg-easy/wg-easy:14 wgpw "${PASSWORD}" \
  | sed -n "s/.*PASSWORD_HASH='\\(.*\\)'/\\1/p")"

docker pull ghcr.io/wg-easy/wg-easy:14
docker run -d \
  --name=wg-easy \
  -e LANG=en \
  -e "WG_HOST=${WG_HOST_IP}" \
  -e "PASSWORD_HASH=${HASH}" \
  -e PORT=51821 \
  -e WG_PORT=51820 \
  -e WG_DEFAULT_ADDRESS=10.8.0.x \
  -e WG_DEFAULT_DNS=1.1.1.1 \
  -e WG_MTU=1420 \
  -e WG_PERSISTENT_KEEPALIVE=25 \
  -e WG_ALLOWED_IPS=0.0.0.0/0 \
  -e WG_DEVICE=eth0 \
  -v "${DATA_DIR}:/etc/wireguard" \
  -v /lib/modules:/lib/modules:ro \
  -p 51820:51820/udp \
  -p 51821:51821/tcp \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl=net.ipv4.conf.all.src_valid_mark=1 \
  --sysctl=net.ipv4.ip_forward=1 \
  --restart unless-stopped \
  ghcr.io/wg-easy/wg-easy:14

# панель не должна перехватывать :51820
mkdir -p /etc/systemd/system/mtproxy-panel.service.d
printf '[Service]\nEnvironment=MTPROXY_DISABLE_WG=1\n' \
  > /etc/systemd/system/mtproxy-panel.service.d/override.conf
systemctl daemon-reload
systemctl restart mtproxy-panel 2>/dev/null || true

sleep 3
docker ps --filter name=wg-easy
docker exec wg-easy wg show || true
echo "UI: http://${WG_HOST_IP}:51821"
echo "PASSWORD: ${PASSWORD}"
