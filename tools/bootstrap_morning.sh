#!/usr/bin/env bash
# Полный подъём: native WG в панели + авто peer с QR. Без wg-easy и без ручных шагов.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1. stop conflicting WG (wg-easy / docker / old iface) =="
docker rm -f wg_server wg-easy 2>/dev/null || true
systemctl disable --now wg-quick@wg0 2>/dev/null || true
wg-quick down wg0 2>/dev/null || true
ip link delete wg0 2>/dev/null || true

# AppArmor wg-quick ломает MTU/iptables на Ubuntu
mkdir -p /etc/apparmor.d/disable
for p in wg wg-quick; do
  [ -f /etc/apparmor.d/$p ] && ln -sf /etc/apparmor.d/$p /etc/apparmor.d/disable/$p
  apparmor_parser -R /etc/apparmor.d/$p 2>/dev/null || true
done
update-alternatives --set iptables /usr/sbin/iptables-nft >/dev/null 2>&1 || true

# панель снова владеет WireGuard
rm -f /etc/systemd/system/mtproxy-panel.service.d/override.conf
systemctl daemon-reload

echo "== 2. git pull =="
git fetch origin cursor/native-vpn-stack-3616 || true
git reset --hard origin/cursor/native-vpn-stack-3616 || git pull origin cursor/native-vpn-stack-3616 || true

echo "== 3. sysctl =="
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null || true
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null || true
sysctl -w net.ipv4.conf.eth0.rp_filter=2 >/dev/null || true
cat >/etc/sysctl.d/99-mtproxy-panel-forward.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.src_valid_mark=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.conf.eth0.rp_filter=2
EOF

echo "== 4. reset WG DB state + auto-provision =="
systemctl restart mtproxy-panel
sleep 2

venv/bin/python - <<'PY'
from database import init_db
init_db()

from vpn_service import WireGuardService
from vpn_health import check_wireguard

svc = WireGuardService()
# Чистый старт: сброс старых ключей (иначе телефон держит протухший туннель)
if svc.get_server_config() is not None:
    print("reset old WG config...")
    svc.reset_server()

peer = svc.ensure_ready()
cfg = svc.get_server_config()
assert cfg is not None and peer is not None
print("=== QR peer ===", peer.name, peer.allocated_ip, peer.qr_filename)
print(peer.config_text)
report = check_wireguard(listen_port=cfg.listen_port, subnet=cfg.subnet)
print(report.format())
if not report.ok:
    raise SystemExit(1)
PY

echo "== 5. enable units + NAT helper =="
cat >/etc/systemd/system/mtproxy-wg-forward.service <<'EOF'
[Unit]
Description=MTProxy panel WireGuard NAT/FORWARD (AppArmor-safe)
After=wg-quick@wg0.service network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=WG_SUBNET=10.8.0.0/24
ExecStart=/bin/bash -c '/usr/local/sbin/mtproxy-wg-nat.sh 2>/dev/null || /root/mtproxy-panel/tools/fix_wg_forward.sh'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable mtproxy-panel wg-quick@wg0 mtproxy-wg-forward.service 2>/dev/null || true
systemctl restart mtproxy-panel
sleep 2
systemctl start mtproxy-wg-forward.service || true
bash tools/fix_wg_forward.sh || true

echo "== 6. selftest =="
bash tools/wg_selftest.sh

echo "== 7. status =="
systemctl is-active mtproxy-panel wg-quick@wg0
ss -ulnp | grep -E '443|51820' || true
ss -tlnp | grep 8000 || true
wg show
curl -sS -o /dev/null -w 'panel_http=%{http_code}\n' http://127.0.0.1:8000/ || true

echo
echo "============================================"
echo "ГОТОВО — ничего вручную создавать не нужно."
echo "  Открой http://$(curl -4 -fsS https://api.ipify.org 2>/dev/null || echo 72.56.92.22):8000/wireguard"
echo "  УДАЛИ все старые туннели на ПК/телефоне."
echo "  Сканируй новый QR (Endpoint теперь UDP 443)."
echo "  В Timeweb firewall (если включён) разреши UDP 443."
echo "  Закрытые 25/587/3389/... к WireGuard НЕ относятся."
echo "============================================"
