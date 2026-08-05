#!/usr/bin/env bash
# После рестарта Docker: DOCKER-USER + FORWARD + MASQUERADE для native wg0.
# Ровно как у проверенного годами рабочего wg-easy (MASQUERADE, не SNAT
# на статичный IP — самовосстанавливается при смене DHCP-адреса).
set -euo pipefail

WAN="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
WAN="${WAN:-eth0}"
SUBNET="${WG_SUBNET:-10.8.0.0/24}"
PORT="${WG_PORT:-443}"

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null 2>&1 || true
iptables -P FORWARD ACCEPT 2>/dev/null || true

iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o wg0 -j ACCEPT

if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  iptables -C DOCKER-USER -i wg0 -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -i wg0 -j ACCEPT
  iptables -C DOCKER-USER -o wg0 -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -o wg0 -j ACCEPT
fi

iptables -t nat -C POSTROUTING -s "${SUBNET}" -o "${WAN}" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -I POSTROUTING 1 -s "${SUBNET}" -o "${WAN}" -j MASQUERADE

iptables -C INPUT -p udp -m udp --dport "${PORT}" -j ACCEPT 2>/dev/null \
  || iptables -I INPUT 1 -p udp -m udp --dport "${PORT}" -j ACCEPT

echo "OK forward wan=${WAN} subnet=${SUBNET} port=${PORT}"
