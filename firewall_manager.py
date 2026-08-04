"""
Маршрутизация VPN на хосте с Docker.

Единственная схема NAT для WireGuard (проверенный паттерн):
  iptables -t nat -A POSTROUTING -s <subnet> -o <WAN> -j MASQUERADE
  iptables -A FORWARD -i wg0 -j ACCEPT / -o wg0 -j ACCEPT
  iptables -P FORWARD ACCEPT
  DOCKER-USER ACCEPT для wg0

nftables используется ТОЛЬКО для input (порты панели/WG/Xray).
Masquerade в nft НЕ ставим — двойной NAT (nft+iptables) ломает return-path.
"""
from __future__ import annotations

import logging
import tempfile
from pathlib import Path

import config
import host_exec

logger = logging.getLogger(__name__)


class FirewallError(RuntimeError):
    """Ошибка применения firewall/NAT."""


def _escape_iface(name: str) -> str:
    if not name.replace("-", "").replace("_", "").isalnum():
        raise FirewallError(f"Некорректное имя интерфейса: {name!r}")
    return name


def detect_wan_interface() -> str:
    """Интерфейс default-route (обычно eth0 / ens3)."""
    result = host_exec.run(["ip", "-4", "route", "show", "default"], check=False)
    for token in result.stdout.split():
        # default via x.x.x.x dev eth0 ...
        pass
    parts = result.stdout.split()
    if "dev" in parts:
        idx = parts.index("dev")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return "eth0"


def _render_input_table(
    *,
    wg_port: int | None,
    xray_port: int | None,
    panel_port: int,
) -> str:
    """Только filter input — без NAT/forward masquerade."""
    lines = [
        f"table inet {config.NFT_TABLE_NAME} {{",
        "  chain input {",
        "    type filter hook input priority filter; policy accept;",
        f"    tcp dport {panel_port} accept comment \"mtproxy-panel\"",
    ]
    if wg_port is not None:
        lines.append(f"    udp dport {wg_port} accept comment \"wireguard\"")
    if xray_port is not None:
        lines.append(f"    tcp dport {xray_port} accept comment \"xray-vless\"")
    lines.extend(["  }", "}"])
    return "\n".join(lines) + "\n"


class FirewallManager:
    def __init__(self) -> None:
        host_exec.require_binaries("nft", "iptables", "ip")

    def ensure(
        self,
        *,
        wg_port: int | None = None,
        xray_port: int | None = None,
        wg_subnet: str | None = None,
        panel_port: int | None = None,
    ) -> None:
        panel = panel_port if panel_port is not None else config.APP_PORT
        table = _render_input_table(
            wg_port=wg_port, xray_port=xray_port, panel_port=panel,
        )
        if self._table_exists():
            host_exec.run(
                ["nft", "delete", "table", "inet", config.NFT_TABLE_NAME],
                check=False,
            )

        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".nft", delete=False) as handle:
            handle.write(table)
            tmp_path = handle.name
        try:
            host_exec.run(["nft", "-f", tmp_path])
        except host_exec.HostExecError as exc:
            raise FirewallError(str(exc)) from exc
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        try:
            host_exec.write_root_file(config.NFT_RULES_PATH, table, mode=0o644)
        except host_exec.HostExecError as exc:
            logger.warning("Не удалось сохранить nftables ruleset: %s", exc)

        self.apply_wireguard_routing(wg_subnet)

        logger.info(
            "firewall ready: wan=%s wg_port=%s xray_port=%s subnet=%s",
            detect_wan_interface(), wg_port, xray_port, wg_subnet,
        )

    def apply_wireguard_routing(self, subnet: str | None) -> None:
        """Чистая IPv4-маршрутизация WG → WAN. Идемпотентно."""
        wan = _escape_iface(detect_wan_interface())
        wg = _escape_iface(config.WG_INTERFACE_NAME)
        network_cidr = ""
        if subnet:
            network_cidr = subnet if "/" in subnet else f"{subnet}/24"

        script = f"""
set -euo pipefail
WAN="{wan}"
WG="{wg}"
SUBNET="{network_cidr}"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null 2>&1 || true
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 2 > "$f" 2>/dev/null || true; done

iptables -P FORWARD ACCEPT 2>/dev/null || true

# Убираем старые наши правила (чтобы не копить дубликаты)
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

if [[ -n "$SUBNET" ]]; then
  # Сносим ВСЕ старые MASQUERADE нашей подсети (в т.ч. ! -o wg0)
  while iptables -t nat -D POSTROUTING -s "$SUBNET" ! -o "$WG" -j MASQUERADE 2>/dev/null; do :; done
  while iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE 2>/dev/null; do :; done
  while iptables -t nat -D POSTROUTING -s "$SUBNET" -j MASQUERADE 2>/dev/null; do :; done
  # Единственное правильное правило: SNAT только на WAN
  iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE
fi

# MSS clamp
while iptables -t mangle -D FORWARD -o "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; do :; done
while iptables -t mangle -D FORWARD -i "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; do :; done
iptables -t mangle -A FORWARD -o "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -i "$WG" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo "WAN=$WAN"
echo "ROUTE_TEST=$(ip -4 route get 1.1.1.1 from 10.66.0.2 iif $WG 2>&1 | tr '\\n' ' ')"
echo "FORWARD=$(iptables -S FORWARD | head -6 | tr '\\n' ';')"
echo "NAT=$(iptables -t nat -S POSTROUTING | tr '\\n' ';')"
"""
        try:
            result = host_exec.run(["bash", "-c", script], timeout=45.0)
            logger.info("WG routing applied: %s", result.stdout.strip())
        except host_exec.HostExecError as exc:
            raise FirewallError(f"Не удалось применить маршрутизацию WG: {exc}") from exc

        try:
            host_exec.write_root_file(
                config.SYSCTL_FORWARD_PATH,
                (
                    "net.ipv4.ip_forward=1\n"
                    "net.ipv4.conf.all.rp_filter=2\n"
                    "net.ipv4.conf.default.rp_filter=2\n"
                    "net.ipv4.conf.all.src_valid_mark=1\n"
                ),
                mode=0o644,
            )
        except host_exec.HostExecError as exc:
            logger.warning("sysctl persist: %s", exc)

    def clear_wireguard(self) -> None:
        if self._table_exists():
            host_exec.run(
                ["nft", "delete", "table", "inet", config.NFT_TABLE_NAME],
                check=False,
            )

    def _table_exists(self) -> bool:
        result = host_exec.run(
            ["nft", "list", "table", "inet", config.NFT_TABLE_NAME],
            check=False,
        )
        return result.ok

    def ensure_ip_forward(self) -> None:
        try:
            host_exec.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        except host_exec.HostExecError as exc:
            raise FirewallError(f"Не удалось включить ip_forward: {exc}") from exc
