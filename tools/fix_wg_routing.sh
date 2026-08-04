#!/usr/bin/env bash
# Рабочий ремонт WireGuard прямо сейчас.
# Запуск: bash tools/fix_wg_routing.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1. код =="
git pull origin cursor/native-vpn-stack-3616 || true

WAN="$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
WAN="${WAN:-eth0}"
WG=wg0
SUBNET=10.66.0.0/24

echo "WAN=$WAN"

echo "== 2. убрать битый PostUp из /etc/wireguard/wg0.conf =="
if [[ -f /etc/wireguard/wg0.conf ]]; then
  sed -i '/^PostUp/d;/^PostDown/d' /etc/wireguard/wg0.conf
  ADDR="$(awk -F'= *' '/^Address/{print $2; exit}' /etc/wireguard/wg0.conf | tr -d '[:space:]')"
  if [[ -n "${ADDR}" ]]; then
    IP="${ADDR%%/*}"; PREF="${ADDR##*/}"; PREF="${PREF:-24}"
    SUBNET="$(echo "$IP" | awk -F. -v p="$PREF" '{print $1"."$2"."$3".0/"p}')"
  fi
fi
# helper больше не нужен в PostUp; на всякий случай сделаем исполняемым
if [[ -f /usr/local/sbin/mtproxy-wg-nat.sh ]]; then
  chmod 755 /usr/local/sbin/mtproxy-wg-nat.sh || true
fi

echo "== 3. поднять wg-quick без PostUp =="
systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
systemctl reset-failed wg-quick@wg0 2>/dev/null || true
# down/up надёжнее restart после failed
wg-quick down wg0 2>/dev/null || true
systemctl restart wg-quick@wg0
sleep 1
systemctl --no-pager --full status wg-quick@wg0 | head -20
wg show

echo "== 4. sysctl + единственный NAT на $WAN =="
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 2 >"$f" 2>/dev/null || true; done

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

# один MASQUERADE на WAN
while iptables -t nat -D POSTROUTING -s "$SUBNET" ! -o "$WG" -j MASQUERADE 2>/dev/null; do :; done
while iptables -t nat -D POSTROUTING -s "$SUBNET" -o eth0 -j MASQUERADE 2>/dev/null; do :; done
while iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE 2>/dev/null; do :; done
while iptables -t nat -D POSTROUTING -s "$SUBNET" -j MASQUERADE 2>/dev/null; do :; done
iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE

iptables -t mangle -C FORWARD -o "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || iptables -t mangle -A FORWARD -o "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -C FORWARD -i "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || iptables -t mangle -A FORWARD -i "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# nft только input (без masquerade)
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

echo "== 5. route test =="
ip -4 route get 1.1.1.1 from 10.66.0.2 iif wg0
echo "NAT:"; iptables -t nat -S POSTROUTING
echo "FORWARD:"; iptables -S FORWARD | head -8

echo "== 6. клиентские .conf для iPhone (AllowedIPs=0.0.0.0/0) =="
mkdir -p data/wireguard/clients
if [[ -x venv/bin/python ]]; then
  venv/bin/python - <<'PY'
from pathlib import Path
import config
from vpn_repository import WireGuardRepository
import wireguard_config, utils

repo = WireGuardRepository()
sc = repo.get_server_config()
if sc is None:
    raise SystemExit("WG не настроен в БД")

clients_dir = config.WG_CONFIG_DIR / "clients"
clients_dir.mkdir(parents=True, exist_ok=True)

# server conf без PostUp
peers = [
    wireguard_config.PeerForConfig(name=p.name, public_key=p.public_key, allocated_ip=p.allocated_ip)
    for p in repo.get_all_peers()
]
server_conf = wireguard_config.render_server_config(
    server_private_key=sc.server_private_key,
    listen_port=sc.listen_port,
    subnet=sc.subnet,
    peers=peers,
)
assert "PostUp" not in server_conf
Path("/etc/wireguard/wg0.conf").write_text(server_conf, encoding="utf-8")
(config.WG_CONFIG_DIR / "wg_confs" / "wg0.conf").write_text(server_conf, encoding="utf-8")

for peer in repo.get_all_peers():
    conf = wireguard_config.render_client_config(
        client_private_key=peer.private_key,
        client_allocated_ip=peer.allocated_ip,
        server_public_key=sc.server_public_key,
        server_endpoint_ip=sc.endpoint_ip,
        server_listen_port=sc.listen_port,
        dns=sc.dns or "1.1.1.1",
    )
    assert "AllowedIPs = 0.0.0.0/0" in conf
    assert "::/0" not in conf
    repo.update_peer_config(peer.id, config_text=conf)
    utils.generate_qr_code(conf, peer.qr_filename)
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in peer.name)
    path = clients_dir / f"{safe}.conf"
    path.write_text(conf, encoding="utf-8")
    print(f"OK {path}")
    print("---")
    print(conf)
    print("---")

# горячий syncconf peer-ов
import subprocess
strip = subprocess.check_output(["wg-quick", "strip", "/etc/wireguard/wg0.conf"], text=True)
subprocess.run(["wg", "syncconf", "wg0", "/dev/stdin"], input=strip, text=True, check=True)
print("wg syncconf OK")
PY
else
  echo "нет venv — bash install.sh"
fi

systemctl restart mtproxy-panel 2>/dev/null || true

echo
echo "============================================"
echo "Сервер: NAT на $WAN, wg-quick без PostUp."
echo
echo "iPhone:"
echo "  1) Удали старый туннель в приложении WireGuard"
echo "  2) Добавь заново QR из панели  ИЛИ файл:"
echo "       data/wireguard/clients/*.conf"
echo "  3) В конфиге должно быть:"
echo "       AllowedIPs = 0.0.0.0/0"
echo "       DNS = 1.1.1.1"
echo "  4) Подключись, открой safari://example.com"
echo "  5) На сервере: wg show   — received/sent должны расти MB"
echo "============================================"
wg show || true
