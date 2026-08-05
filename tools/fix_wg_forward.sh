#!/usr/bin/env bash
# После рестарта Docker: DOCKER-USER + FORWARD для native wg0.
set -euo pipefail

WAN="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
WAN="${WAN:-eth0}"
SUBNET="${WG_SUBNET:-10.8.0.0/24}"

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
iptables -P FORWARD ACCEPT 2>/dev/null || true

if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  iptables -C DOCKER-USER -i wg0 -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER -i wg0 -j ACCEPT
  iptables -C DOCKER-USER -o wg0 -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER -o wg0 -j ACCEPT
fi

iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT

if ip link show wg0 >/dev/null 2>&1; then
  iptables -t nat -C POSTROUTING -s "${SUBNET}" -o "${WAN}" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "${SUBNET}" -o "${WAN}" -j MASQUERADE
fi

echo "OK forward wan=${WAN} subnet=${SUBNET}"
