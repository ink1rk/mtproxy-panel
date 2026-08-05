#!/usr/bin/env bash
# После рестарта Docker: DOCKER-USER + FORWARD + SNAT для native wg0.
set -euo pipefail

WAN="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
WAN="${WAN:-eth0}"
SUBNET="${WG_SUBNET:-10.8.0.0/24}"
PORT="${WG_PORT:-443}"
SRC_IP="$(ip -4 -o addr show dev "${WAN}" 2>/dev/null | awk '{print $4; exit}' | cut -d/ -f1)"

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null 2>&1 || true
iptables -P FORWARD ACCEPT 2>/dev/null || true

iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o wg0 -j ACCEPT
iptables -C FORWARD -i wg0 -p icmp -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i wg0 -p icmp -j ACCEPT
iptables -C FORWARD -o wg0 -p icmp -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o wg0 -p icmp -j ACCEPT

if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  iptables -C DOCKER-USER -i wg0 -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -i wg0 -j ACCEPT
  iptables -C DOCKER-USER -o wg0 -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -o wg0 -j ACCEPT
fi

if [[ -n "${SRC_IP}" ]]; then
  iptables -t nat -C POSTROUTING -s "${SUBNET}" -o "${WAN}" -j SNAT --to-source "${SRC_IP}" 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s "${SUBNET}" -o "${WAN}" -j SNAT --to-source "${SRC_IP}"
else
  iptables -t nat -C POSTROUTING -s "${SUBNET}" -o "${WAN}" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s "${SUBNET}" -o "${WAN}" -j MASQUERADE
fi

iptables -C INPUT -p udp -m udp --dport "${PORT}" -j ACCEPT 2>/dev/null \
  || iptables -I INPUT 1 -p udp -m udp --dport "${PORT}" -j ACCEPT

iptables -t mangle -C FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || iptables -t mangle -A FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo "OK forward wan=${WAN} subnet=${SUBNET} port=${PORT} snat=${SRC_IP:-masq}"
