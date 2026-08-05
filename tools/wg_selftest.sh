#!/usr/bin/env bash
# Netns-клиент против native wg0. Ключи только в /etc/wireguard/ (AppArmor).
# Подсеть берётся с адреса wg0 (10.8.0.0/24 или 10.66.0.0/24).
set -euo pipefail
cd "$(dirname "$0")/.."

NS="mtproxy-wg-test"
IFACE_C="wgt"
VETH_H="veth-wgt-h"
VETH_N="veth-wgt-n"
HOST_VETH_IP="192.168.233.1"
NS_VETH_IP="192.168.233.2"

cleanup() {
  ip netns del "${NS}" 2>/dev/null || true
  ip link del "${VETH_H}" 2>/dev/null || true
  PUB="$(cat /etc/wireguard/mtproxy-test.pub 2>/dev/null || true)"
  if [[ -n "${PUB}" ]] && ip link show wg0 >/dev/null 2>&1; then
    wg set wg0 peer "${PUB}" remove 2>/dev/null || true
  fi
  rm -f /etc/wireguard/mtproxy-test.key /etc/wireguard/mtproxy-test.pub /etc/wireguard/mtproxy-test.conf
}
trap cleanup EXIT

[[ "${EUID}" -eq 0 ]] || { echo "нужен root"; exit 1; }
ip link show wg0 >/dev/null 2>&1 || { echo "wg0 не поднят"; exit 1; }

WG_ADDR="$(ip -4 -o addr show dev wg0 | awk '{print $4; exit}')"
WG_IP="${WG_ADDR%%/*}"
BASE="$(echo "${WG_IP}" | awk -F. '{print $1"."$2"."$3}')"
CLIENT_IP="${BASE}.250"
GATEWAY_IP="${BASE}.1"
echo "selftest subnet base=${BASE} client=${CLIENT_IP} gw=${GATEWAY_IP}"

umask 077
wg genkey | tee /etc/wireguard/mtproxy-test.key | wg pubkey > /etc/wireguard/mtproxy-test.pub
chmod 600 /etc/wireguard/mtproxy-test.key
CLIENT_PUB="$(cat /etc/wireguard/mtproxy-test.pub)"
CLIENT_PRIV="$(cat /etc/wireguard/mtproxy-test.key)"
SERVER_PUB="$(wg show wg0 public-key)"
LISTEN_PORT="$(wg show wg0 listen-port)"
wg set wg0 peer "${CLIENT_PUB}" allowed-ips "${CLIENT_IP}/32"

cat > /etc/wireguard/mtproxy-test.conf <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV}

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${HOST_VETH_IP}:${LISTEN_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/mtproxy-test.conf

ip netns del "${NS}" 2>/dev/null || true
ip link del "${VETH_H}" 2>/dev/null || true
ip netns add "${NS}"
ip link add "${VETH_H}" type veth peer name "${VETH_N}"
ip addr add "${HOST_VETH_IP}/24" dev "${VETH_H}"
ip link set "${VETH_H}" up
ip link set "${VETH_N}" netns "${NS}"

ip netns exec "${NS}" bash -c "
set -e
ip link set ${VETH_N} up
ip link set lo up
ip addr add ${NS_VETH_IP}/24 dev ${VETH_N}
ip link add ${IFACE_C} type wireguard
wg setconf ${IFACE_C} /etc/wireguard/mtproxy-test.conf
ip address add ${CLIENT_IP}/32 dev ${IFACE_C}
ip link set ${IFACE_C} up mtu 1280
ip route add ${HOST_VETH_IP}/32 dev ${VETH_N}
ip route add default dev ${IFACE_C}
ping -c 3 -W 2 ${GATEWAY_IP}
ping -c 3 -W 3 1.1.1.1
"

echo "SELFTEST OK"
wg show
