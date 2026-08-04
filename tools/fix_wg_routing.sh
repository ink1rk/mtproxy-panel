#!/usr/bin/env bash
# Миграция на WireGuard Docker как у wg-easy.
# Запуск: bash tools/fix_wg_routing.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== pull =="
git pull origin cursor/native-vpn-stack-3616 || true

echo "== гасим native wg-quick (освобождаем :51820) =="
systemctl disable --now wg-quick@wg0 2>/dev/null || true
wg-quick down wg0 2>/dev/null || true
ip link delete wg0 2>/dev/null || true

echo "== docker image =="
docker pull lscr.io/linuxserver/wireguard:latest

echo "== пересоздаём контейнер через панель/python =="
systemctl restart mtproxy-panel 2>/dev/null || true
sleep 2

if [[ ! -x venv/bin/python ]]; then
  echo "нет venv — сначала: bash install.sh"
  exit 1
fi

venv/bin/python - <<'PY'
from vpn_service import WireGuardService, VpnServiceError

svc = WireGuardService()
cfg = svc.get_server_config()
if cfg is None:
    raise SystemExit("WG не настроен в панели — открой /wireguard и нажми «Настроить»")

svc._refresh_peer_client_configs(cfg)
conf = svc._render_conf(cfg)
svc._manager.ensure_server_running(
    conf_text=conf,
    listen_port=cfg.listen_port,
    subnet=cfg.subnet,
)
from vpn_health import check_wireguard
report = check_wireguard(listen_port=cfg.listen_port, subnet=cfg.subnet)
print(report.format())
if not report.ok:
    raise SystemExit(1)

# показать клиентский conf
from pathlib import Path
import config
clients = sorted((config.WG_CONFIG_DIR / "clients").glob("*.conf"))
for p in clients:
    print("CLIENT", p)
    print(p.read_text(encoding="utf-8"))
PY

echo
echo "== docker ps / wg show / NAT inside =="
docker ps --filter name=wg_server --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
docker exec wg_server wg show || true
docker exec wg_server iptables -t nat -S POSTROUTING || true
docker exec wg_server iptables -S FORWARD | head -10 || true

echo
echo "============================================"
echo "Схема как wg-easy: Docker + MASQUERADE -o eth0"
echo "iPhone: удали старый туннель → новый QR из панели"
echo "  AllowedIPs = 0.0.0.0/0"
echo "Потом: docker exec wg_server wg show"
echo "  transfer должен расти в KB/MB при открытии сайтов"
echo "============================================"
