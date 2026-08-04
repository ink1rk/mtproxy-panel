#!/usr/bin/env bash
# Полный подъём стека на VPS: native WG (формат wg-easy) + panel + selftest.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1. stop conflicting WG containers =="
docker rm -f wg_server wg-easy 2>/dev/null || true
systemctl disable --now wg-quick@wg0 2>/dev/null || true
wg-quick down wg0 2>/dev/null || true
ip link delete wg0 2>/dev/null || true

echo "== 2. git pull =="
git pull origin cursor/native-vpn-stack-3616 || true

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

echo "== 4. restart panel (migrate DB + ensure WG) =="
systemctl restart mtproxy-panel
sleep 3

venv/bin/python - <<'PY'
from database import init_db
init_db()

from vpn_service import WireGuardService
from vpn_health import check_wireguard
import config

svc = WireGuardService()
cfg = svc.get_server_config()
if cfg is None:
    print("WG не настроен — создаю сервер...")
    cfg = svc.setup_server(
        listen_port=config.WG_DEFAULT_PORT,
        subnet=config.WG_DEFAULT_SUBNET,
        dns=config.WG_DEFAULT_DNS,
    )

# Пересоздаём единственный peer iphone с PSK / MTU1280 / Address/24
for p in list(svc.list_peers()):
    print(f"delete old peer {p.name}")
    svc.delete_peer(p.id)

peer = svc.add_peer("iphone")
print("=== NEW CLIENT CONFIG (import on phone) ===")
print(peer.config_text)
print("=== QR ===", peer.qr_filename)

report = check_wireguard(listen_port=cfg.listen_port, subnet=cfg.subnet)
print(report.format())
if not report.ok:
    raise SystemExit(1)
PY

echo "== 5. enable units =="
systemctl enable mtproxy-panel wg-quick@wg0 mtproxy-wg-forward.service 2>/dev/null || true
bash tools/fix_wg_forward.sh || true

echo "== 6. selftest =="
bash tools/wg_selftest.sh

echo "== 7. status =="
systemctl is-active mtproxy-panel wg-quick@wg0
ss -ulnp | grep 51820
ss -tlnp | grep 8000
wg show
curl -sS -o /dev/null -w 'panel_http=%{http_code}\n' http://127.0.0.1:8000/ || true

echo
echo "============================================"
echo "ГОТОВО. Утром:"
echo "  1) Открой http://72.56.92.22:8000/wireguard"
echo "  2) Удали старый туннель на iPhone"
echo "  3) Сканируй QR peer 'iphone' (новый: PSK + MTU 1280)"
echo "  4) wg show — transfer должен расти"
echo "============================================"
