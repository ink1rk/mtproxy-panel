#!/usr/bin/env bash
# Срочный фикс: Docker FORWARD DROP режет интернет через WireGuard.
# Симптом: handshake OK, transfer ~1–3 KiB, сайты не открываются.
# Запуск: bash tools/fix_wg_forward.sh
set -euo pipefail

IFACE="${IFACE:-wg0}"
SUBNET="${SUBNET:-10.66.0.0/24}"

echo "== ip_forward / rp_filter =="
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.default.rp_filter=2
sysctl -w net.ipv4.conf.all.src_valid_mark=1
for d in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 2 > "$d" 2>/dev/null || true; done

echo "== iptables FORWARD ACCEPT + wg0 =="
iptables -P FORWARD ACCEPT
iptables -C FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$IFACE" -j ACCEPT
iptables -C FORWARD -o "$IFACE" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o "$IFACE" -j ACCEPT

if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  echo "== DOCKER-USER accept wg0 =="
  iptables -C DOCKER-USER -i "$IFACE" -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -i "$IFACE" -j ACCEPT
  iptables -C DOCKER-USER -o "$IFACE" -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -o "$IFACE" -j ACCEPT
else
  echo "== DOCKER-USER нет (ok, если Docker не трогал filter) =="
fi

echo "== iptables MASQUERADE =="
iptables -t nat -C POSTROUTING -s "$SUBNET" ! -o "$IFACE" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$SUBNET" ! -o "$IFACE" -j MASQUERADE

echo "== TCPMSS clamp =="
iptables -t mangle -C FORWARD -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || iptables -t mangle -A FORWARD -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -C FORWARD -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || iptables -t mangle -A FORWARD -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo "== nftables masquerade (если таблицы нет — пропускаем) =="
if nft list table inet mtproxy-panel >/dev/null 2>&1; then
  nft list table inet mtproxy-panel | grep -E 'masquerade|wg0' || true
fi

echo
echo "== итог =="
iptables -S FORWARD | head -8
iptables -S DOCKER-USER 2>/dev/null | head -8 || true
iptables -t nat -S POSTROUTING
wg show || true
echo
echo "OK. Переподключи VPN на телефоне и снова: wg show"
echo "transfer должен расти (десятки/сотни KiB), не 1–3 KiB."
