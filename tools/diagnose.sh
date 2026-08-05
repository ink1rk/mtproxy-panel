#!/usr/bin/env bash
# Полная диагностика native VPN + MTProxy.
set -uo pipefail
cd "$(dirname "$0")/.."

run() { echo; echo ">>> $*"; "$@"; }

run uname -a
run cat /proc/sys/net/ipv4/ip_forward
run systemctl status mtproxy-panel --no-pager -l | head -30
run systemctl status wg-quick@wg0 --no-pager -l | head -40
run systemctl status xray --no-pager -l | head -40
run ss -ulnp
run ss -tlnp | head -40
run wg show
run nft list table inet mtproxy-panel
run ip -4 route
run cat /etc/wireguard/wg0.conf
run head -80 /usr/local/etc/xray/config.json
run docker ps -a
run journalctl -u wg-quick@wg0 -n 40 --no-pager
run journalctl -u xray -n 40 --no-pager
