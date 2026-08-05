#!/usr/bin/env bash
# Перевод/починка WireGuard → native wg-quick@wg0 (проверено на Timeweb).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== pull =="
git pull origin cursor/native-vpn-stack-3616 || true

echo "== stop docker wg_server (конфликт :51820) =="
docker rm -f wg_server 2>/dev/null || true

echo "== host forwarding =="
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null || true

if [[ ! -x venv/bin/python ]]; then
  echo "нет venv — сначала: bash install.sh"
  exit 1
fi

echo "== recreate native WG via panel =="
systemctl restart mtproxy-panel 2>/dev/null || true
sleep 2

venv/bin/python - <<'PY'
from vpn_service import WireGuardService
from vpn_health import check_wireguard
import config

svc = WireGuardService()
cfg = svc.get_server_config()
if cfg is None:
    raise SystemExit("WG не настроен — открой /wireguard и нажми «Настроить»")

svc._refresh_peer_client_configs(cfg)
conf = svc._render_conf(cfg)
svc._manager.ensure_server_running(
    conf_text=conf,
    listen_port=cfg.listen_port,
    subnet=cfg.subnet,
)
report = check_wireguard(listen_port=cfg.listen_port, subnet=cfg.subnet)
print(report.format())
if not report.ok:
    raise SystemExit(1)
for p in svc.list_peers():
    print("CLIENT", p.name)
    print(p.config_text)
PY

echo
echo "== status =="
systemctl is-active wg-quick@wg0 || true
wg show || true
ss -ulnp | grep -E ':51820\b' || echo "UDP 51820 missing"
iptables -t nat -S POSTROUTING | grep -E '10\.66|MASQUERADE' || true
iptables -S DOCKER-USER 2>/dev/null | head -10 || true

echo
echo "== selftest =="
bash tools/wg_selftest.sh || echo "WARN selftest"

echo
echo "============================================"
echo "Native wg-quick@wg0 готов"
echo "iPhone: тот же QR из панели (или переимпорт)"
echo "Проверка: wg show   — transfer должен расти"
echo "============================================"
