#!/usr/bin/env bash
# Полный ремонт WireGuard по рецепту wg-easy + фикс Docker DNAT.
# Запуск: bash tools/fix_wg_routing.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== pull =="
git pull origin cursor/native-vpn-stack-3616 || true

echo "== гасим native wg-quick (освобождаем :51820) =="
systemctl disable --now wg-quick@wg0 2>/dev/null || true
wg-quick down wg0 2>/dev/null || true
ip link delete wg0 2>/dev/null || true

echo "== удаляем stale wg_server =="
docker rm -f wg_server 2>/dev/null || true

echo "== чиним Docker iptables (проверенный фикс DNAT) =="
if [[ ! -x venv/bin/python ]]; then
  echo "нет venv — сначала: bash install.sh"
  exit 1
fi

venv/bin/python - <<'PY'
from docker_iptables import ensure_docker_iptables, DockerIptablesError, docker_nat_chain_exists
try:
    info = ensure_docker_iptables(force_repair=not docker_nat_chain_exists())
    print("docker_iptables:", info)
except DockerIptablesError as exc:
    print("WARN docker_iptables:", exc)
    print("Будет fallback на network_mode=host")
PY

echo "== docker image =="
docker pull lscr.io/linuxserver/wireguard:latest

echo "== host forwarding =="
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null || true
bash tools/fix_wg_forward.sh || true

echo "== пересоздаём контейнер через панель/python =="
systemctl restart mtproxy-panel 2>/dev/null || true
sleep 2

venv/bin/python - <<'PY'
import config
from vpn_service import WireGuardService

svc = WireGuardService()
cfg = svc.get_server_config()
if cfg is None:
    raise SystemExit("WG не настроен в панели — открой /wireguard и нажми «Настроить»")

print(
    f"prefer_mode={config.WG_NETWORK_MODE} wan={config.WG_DOCKER_WAN_IFACE} "
    f"port={cfg.listen_port} subnet={cfg.subnet}"
)
svc._refresh_peer_client_configs(cfg)
conf = svc._render_conf(cfg)
# Убедимся что PostUp = wg-easy (wg0, не %i)
assert "FORWARD -i wg0" in conf, conf
assert "%i" not in conf.split("PostUp", 1)[-1].split("\n", 1)[0]
assert "::/0" not in conf
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

clients = sorted((config.WG_CONFIG_DIR / "clients").glob("*.conf"))
for p in clients:
    text = p.read_text(encoding="utf-8")
    assert "AllowedIPs = 0.0.0.0/0" in text, text
    assert "::/0" not in text, text
    print("CLIENT", p)
    print(text)
PY

echo
echo "== docker / network / wg / NAT =="
docker ps --filter name=wg_server --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
docker inspect -f 'NetworkMode={{.HostConfig.NetworkMode}}' wg_server || true
docker exec wg_server wg show || true
docker exec wg_server iptables -t nat -S POSTROUTING || true
docker exec wg_server iptables -S FORWARD | head -15 || true
ss -ulnp | grep -E ':51820\b' || echo "UDP 51820: НЕ слушается"
iptables -t nat -L DOCKER -n 2>/dev/null | head -5 || echo "host nat/DOCKER: нет"

echo
echo "== selftest (netns client -> ping 1.1.1.1) =="
bash tools/wg_selftest.sh || echo "WARN: selftest не прошёл — смотри вывод выше"

echo
echo "============================================"
echo "Рецепт: wg-easy PostUp + Docker bridge (или host fallback)"
echo "iPhone: удали старый туннель → новый QR из панели"
echo "  AllowedIPs = 0.0.0.0/0   (без ::/0)"
echo "Проверка: docker exec wg_server wg show"
echo "  transfer должен расти в KB/MB"
echo "============================================"
