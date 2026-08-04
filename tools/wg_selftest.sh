#!/usr/bin/env bash
# Реальная проверка туннеля: ephemeral peer в network namespace + veth к хосту.
# Успех = ping 10.66.0.1 И ping 1.1.1.1 через WG (NAT работает).
set -euo pipefail
cd "$(dirname "$0")/.."

NS="mtproxy-wg-test"
CLIENT_IP="10.66.0.250"
SERVER_TUN="10.66.0.1"
IFACE_C="wgt"
VETH_H="veth-wgt-h"
VETH_N="veth-wgt-n"
HOST_VETH_IP="192.168.233.1"
NS_VETH_IP="192.168.233.2"

cleanup() {
  ip netns del "${NS}" 2>/dev/null || true
  ip link del "${VETH_H}" 2>/dev/null || true
  PUB="$(cat /tmp/mtproxy-wg-test.pub 2>/dev/null || true)"
  if [[ -n "${PUB}" ]] && docker ps --format '{{.Names}}' | grep -qx wg_server; then
    docker exec wg_server wg set wg0 peer "${PUB}" remove 2>/dev/null || true
  fi
  rm -f /tmp/mtproxy-wg-test.key /tmp/mtproxy-wg-test.pub
}
trap cleanup EXIT

if [[ "${EUID}" -ne 0 ]]; then
  echo "нужен root"
  exit 1
fi
command -v wg >/dev/null || { echo "нет wg (wireguard-tools)"; exit 1; }
docker ps --format '{{.Names}}' | grep -qx wg_server || {
  echo "контейнер wg_server не running"
  exit 1
}

umask 077
wg genkey | tee /tmp/mtproxy-wg-test.key | wg pubkey > /tmp/mtproxy-wg-test.pub
CLIENT_PRIV_FILE=/tmp/mtproxy-wg-test.key
CLIENT_PUB="$(cat /tmp/mtproxy-wg-test.pub)"
SERVER_PUB="$(docker exec wg_server wg show wg0 public-key | tr -d '\r')"
LISTEN_PORT="$(docker exec wg_server wg show wg0 listen-port | tr -d '\r')"
NETMODE="$(docker inspect -f '{{.HostConfig.NetworkMode}}' wg_server)"

docker exec wg_server wg set wg0 peer "${CLIENT_PUB}" allowed-ips "${CLIENT_IP}/32"

# Порт на хосте: при bridge — published; при host — listen port.
if [[ "${NETMODE}" == "host" ]]; then
  HOST_UDP_PORT="${LISTEN_PORT}"
else
  HOST_UDP_PORT="$(docker inspect -f '{{with (index (index .NetworkSettings.Ports "51820/udp") 0)}}{{.HostPort}}{{end}}' wg_server 2>/dev/null || true)"
  HOST_UDP_PORT="${HOST_UDP_PORT:-51820}"
fi
ENDPOINT="${HOST_VETH_IP}:${HOST_UDP_PORT}"

ip netns del "${NS}" 2>/dev/null || true
ip link del "${VETH_H}" 2>/dev/null || true
ip netns add "${NS}"

ip link add "${VETH_H}" type veth peer name "${VETH_N}"
ip addr add "${HOST_VETH_IP}/24" dev "${VETH_H}"
ip link set "${VETH_H}" up
ip link set "${VETH_N}" netns "${NS}"
ip netns exec "${NS}" ip addr add "${NS_VETH_IP}/24" dev "${VETH_N}"
ip netns exec "${NS}" ip link set "${VETH_N}" up
ip netns exec "${NS}" ip link set lo up

# WireGuard iface в netns
ip link add "${IFACE_C}" type wireguard
ip link set "${IFACE_C}" netns "${NS}"
ip netns exec "${NS}" wg set "${IFACE_C}" \
  private-key "${CLIENT_PRIV_FILE}" \
  listen-port 0 \
  peer "${SERVER_PUB}" \
  endpoint "${ENDPOINT}" \
  allowed-ips 0.0.0.0/0 \
  persistent-keepalive 25
ip netns exec "${NS}" ip address add "${CLIENT_IP}/32" dev "${IFACE_C}"
ip netns exec "${NS}" ip link set "${IFACE_C}" up mtu 1420
# До endpoint — через veth; весь остальной трафик — в туннель.
ip netns exec "${NS}" ip route add "${HOST_VETH_IP}/32" dev "${VETH_N}"
ip netns exec "${NS}" ip route add default dev "${IFACE_C}"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
# чтобы host принял UDP с veth на docker-proxy
iptables -C INPUT -i "${VETH_H}" -p udp --dport "${HOST_UDP_PORT}" -j ACCEPT 2>/dev/null \
  || iptables -I INPUT -i "${VETH_H}" -p udp --dport "${HOST_UDP_PORT}" -j ACCEPT

echo "netmode=${NETMODE} endpoint=${ENDPOINT} server_pub=${SERVER_PUB:0:16}..."

echo "== ping tunnel gateway ${SERVER_TUN} =="
if ! ip netns exec "${NS}" ping -c 3 -W 2 "${SERVER_TUN}"; then
  echo "FAIL: нет L3 до ${SERVER_TUN}"
  docker exec wg_server wg show
  ip netns exec "${NS}" wg show
  exit 1
fi

echo "== ping 1.1.1.1 через NAT =="
if ! ip netns exec "${NS}" ping -c 3 -W 3 1.1.1.1; then
  echo "FAIL: туннель есть, интернета нет (MASQUERADE/FORWARD)"
  docker exec wg_server iptables -t nat -S POSTROUTING
  docker exec wg_server iptables -S FORWARD | head -20
  docker exec wg_server wg show
  exit 1
fi

echo "SELFTEST OK"
docker exec wg_server wg show
