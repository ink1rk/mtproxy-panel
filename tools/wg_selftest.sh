#!/usr/bin/env bash
# Netns-клиент против native wg0. Ключи только в /etc/wireguard/ (AppArmor).
set -euo pipefail
cd "$(dirname "$0")/.."

NS="mtproxy-wg-test"
CLIENT_IP="10.66.0.250"
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

umask 077
wg genkey | tee /etc/wireguard/mtproxy-test.key | wg pubkey > /etc/wireguard/mtproxy-test.pub
chmod 600 /etc/wireguard/mtproxy-test.key
CLIENT_PUB="$(cat /etc/wireguard/mtproxy-test.pub)"
CLIENT_PRIV="$(cat /etc/wireguard/mtproxy-test.key)"
SERVER_PUB="$(wg show wg0 public-key)"
wg set wg0 peer "${CLIENT_PUB}" allowed-ips "${CLIENT_IP}/32"

cat > /etc/wireguard/mtproxy-test.conf <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV}

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${HOST_VETH_IP}:51820
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
ip link set ${IFACE_C} up mtu 1420
ip route add ${HOST_VETH_IP}/32 dev ${VETH_N}
ip route add default dev ${IFACE_C}
ping -c 3 -W 2 10.66.0.1
ping -c 3 -W 3 1.1.1.1
"

echo "SELFTEST OK"
wg show
