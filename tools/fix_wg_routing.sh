#!/usr/bin/env bash
# Полный ремонт маршрутизации WireGuard (не Docker).
# Симптом: handshake OK, transfer ~2 KiB, сайты не открываются.
#
# 1) Один NAT: iptables MASQUERADE -o <WAN>
# 2) Убирает nft masquerade (двойной NAT)
# 3) Пересобирает клиентские .conf БЕЗ ::/0 (IPv6 blackhole)
# 4) Тест ip route get
#
# Запуск: bash tools/fix_wg_routing.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== pull =="
git pull origin cursor/native-vpn-stack-3616 || true

WAN="$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
WAN="${WAN:-eth0}"
WG=wg0
SUBNET=10.66.0.0/24
if [[ -f /etc/wireguard/wg0.conf ]]; then
  ADDR="$(awk -F'= *' '/^Address/{print $2; exit}' /etc/wireguard/wg0.conf | tr -d '[:space:]')"
  if [[ -n "${ADDR}" ]]; then
    IP="${ADDR%%/*}"; PREF="${ADDR##*/}"; PREF="${PREF:-24}"
    SUBNET="$(echo "$IP" | awk -F. -v p="$PREF" '{print $1"."$2"."$3".0/"p}')"
  fi
fi

echo "WAN=$WAN SUBNET=$SUBNET"

echo "== sysctl =="
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.default.rp_filter=2
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 2 >"$f" 2>/dev/null || true; done

echo "== убираем nft masquerade (оставляем только input) =="
nft delete table inet mtproxy-panel 2>/dev/null || true
nft -f - <<EOF
table inet mtproxy-panel {
  chain input {
    type filter hook input priority filter; policy accept;
    tcp dport 8000 accept
    udp dport 51820 accept
  }
}
EOF

echo "== чистый iptables NAT на $WAN =="
iptables -P FORWARD ACCEPT
while iptables -D FORWARD -i "$WG" -j ACCEPT 2>/dev/null; do :; done
while iptables -D FORWARD -o "$WG" -j ACCEPT 2>/dev/null; do :; done
iptables -I FORWARD 1 -i "$WG" -j ACCEPT
iptables -I FORWARD 1 -o "$WG" -j ACCEPT

if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  while iptables -D DOCKER-USER -i "$WG" -j ACCEPT 2>/dev/null; do :; done
  while iptables -D DOCKER-USER -o "$WG" -j ACCEPT 2>/dev/null; do :; done
  iptables -I DOCKER-USER 1 -i "$WG" -j ACCEPT
  iptables -I DOCKER-USER 1 -o "$WG" -j ACCEPT
fi

# Снести ВСЕ старые MASQUERADE нашей подсети
while iptables -t nat -D POSTROUTING -s "$SUBNET" ! -o "$WG" -j MASQUERADE 2>/dev/null; do :; done
while iptables -t nat -D POSTROUTING -s "$SUBNET" -o eth0 -j MASQUERADE 2>/dev/null; do :; done
while iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE 2>/dev/null; do :; done
while iptables -t nat -D POSTROUTING -s "$SUBNET" -j MASQUERADE 2>/dev/null; do :; done
iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE

iptables -t mangle -C FORWARD -o "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || iptables -t mangle -A FORWARD -o "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -C FORWARD -i "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || iptables -t mangle -A FORWARD -i "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# helper для PostUp
install -m 755 /dev/stdin /usr/local/sbin/mtproxy-wg-nat.sh <<'EOS'
#!/bin/bash
set -euo pipefail
WAN="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
WAN="${WAN:-eth0}"
WG=wg0
SUBNET=10.66.0.0/24
if [[ -f /etc/wireguard/wg0.conf ]]; then
  ADDR="$(awk -F'= *' '/^Address/{print $2; exit}' /etc/wireguard/wg0.conf | tr -d '[:space:]')"
  if [[ -n "${ADDR}" ]]; then
    IP="${ADDR%%/*}"; PREF="${ADDR##*/}"; PREF="${PREF:-24}"
    SUBNET="$(echo "$IP" | awk -F. -v p="$PREF" '{print $1"."$2"."$3".0/"p}')"
  fi
fi
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -C FORWARD -i "$WG" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$WG" -j ACCEPT
iptables -C FORWARD -o "$WG" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o "$WG" -j ACCEPT
if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  iptables -C DOCKER-USER -i "$WG" -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -i "$WG" -j ACCEPT
  iptables -C DOCKER-USER -o "$WG" -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -o "$WG" -j ACCEPT
fi
iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE
EOS

# PostUp в wg0.conf
if [[ -f /etc/wireguard/wg0.conf ]]; then
  if ! grep -q 'mtproxy-wg-nat.sh' /etc/wireguard/wg0.conf; then
    sed -i '/^ListenPort/a PostUp = /usr/local/sbin/mtproxy-wg-nat.sh' /etc/wireguard/wg0.conf
  fi
fi

echo "== route test =="
ip -4 route get 1.1.1.1 from 10.66.0.2 iif wg0 || true
echo "NAT:"; iptables -t nat -S POSTROUTING
echo "FORWARD:"; iptables -S FORWARD | head -8

echo "== пересборка клиентских конфигов (без ::/0) + restart панели =="
if [[ -x venv/bin/python ]]; then
  venv/bin/python - <<'PY'
import config
from vpn_repository import WireGuardRepository
from vpn_service import WireGuardService
import wireguard_config, utils

repo = WireGuardRepository()
sc = repo.get_server_config()
if not sc:
    print("WG не настроен в БД — пропуск refresh клиентов")
    raise SystemExit(0)
svc = WireGuardService()
svc._refresh_peer_client_configs(sc)
# переписать server conf + reload + routing
conf = svc._render_conf(sc)
svc._manager.ensure_server_running(
    conf_text=conf, listen_port=sc.listen_port, subnet=sc.subnet,
)
print("peers refreshed, server restarted with new routing")
for p in repo.get_all_peers():
    assert "::/0" not in p.config_text, p.name
    print(f"  peer {p.name}: AllowedIPs OK (no IPv6)")
PY
else
  echo "venv нет — перезапустите: bash install.sh"
fi

systemctl restart mtproxy-panel 2>/dev/null || true
systemctl restart mtproxy-wg-forward 2>/dev/null || true

echo
echo "=========================================="
echo "ОБЯЗАТЕЛЬНО на телефоне:"
echo "  1) УДАЛИ старый профиль WireGuard"
echo "  2) В панели скачай НОВЫЙ QR / .conf"
echo "  3) В .conf должно быть: AllowedIPs = 0.0.0.0/0"
echo "     (БЕЗ ::/0)"
echo "  4) Подключись и: wg show   — transfer должен расти быстро"
echo "=========================================="
wg show || true
