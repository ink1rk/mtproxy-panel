"""
Firewall/NAT для native VPN-стека.

Критично: на хосте с Docker filter FORWARD = DROP. nftables ACCEPT в нашей
таблице НЕ отменяет поздний DROP Docker → handshake WG есть (1–3 KiB),
интернета нет. Поэтому параллельно правим iptables DOCKER-USER / FORWARD
и дублируем MASQUERADE в iptables nat.
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


def _render_table(
    *,
    wg_port: int | None,
    xray_port: int | None,
    panel_port: int,
    wg_subnet: str | None,
    wg_iface: str,
) -> str:
    iface = _escape_iface(wg_iface)
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
    lines.extend(
        [
            "  }",
            "",
            "  chain forward {",
            "    type filter hook forward priority filter; policy accept;",
            f"    iifname \"{iface}\" accept comment \"wg-forward-in\"",
            f"    oifname \"{iface}\" accept comment \"wg-forward-out\"",
            "  }",
            "",
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat; policy accept;",
        ]
    )
    if wg_subnet:
        lines.append(
            f"    ip saddr {wg_subnet} oifname != \"{iface}\" "
            f"masquerade comment \"wg-nat\""
        )
    lines.extend(["  }", "}"])
    return "\n".join(lines) + "\n"


class FirewallManager:
    """nftables + iptables(Docker) для рабочего WG NAT."""

    def __init__(self) -> None:
        host_exec.require_binaries("nft")

    def ensure(
        self,
        *,
        wg_port: int | None = None,
        xray_port: int | None = None,
        wg_subnet: str | None = None,
        panel_port: int | None = None,
    ) -> None:
        panel = panel_port if panel_port is not None else config.APP_PORT
        table = _render_table(
            wg_port=wg_port,
            xray_port=xray_port,
            panel_port=panel,
            wg_subnet=wg_subnet,
            wg_iface=config.WG_INTERFACE_NAME,
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

        # Docker FORWARD DROP — главная причина «handshake есть, интернета нет».
        self._ensure_iptables_forward_and_nat(wg_subnet)

        logger.info(
            "firewall ready: wg_port=%s xray_port=%s subnet=%s",
            wg_port, xray_port, wg_subnet,
        )

    def _ensure_iptables_forward_and_nat(self, subnet: str | None) -> None:
        iface = config.WG_INTERFACE_NAME
        network_cidr = ""
        if subnet:
            network_cidr = subnet if "/" in subnet else f"{subnet}/24"

        script = f"""
set -e
IFACE="{iface}"
SUBNET="{network_cidr}"

iptables -P FORWARD ACCEPT 2>/dev/null || true
ip6tables -P FORWARD ACCEPT 2>/dev/null || true

iptables -C FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$IFACE" -j ACCEPT
iptables -C FORWARD -o "$IFACE" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o "$IFACE" -j ACCEPT

if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  iptables -C DOCKER-USER -i "$IFACE" -j ACCEPT 2>/dev/null \\
    || iptables -I DOCKER-USER 1 -i "$IFACE" -j ACCEPT
  iptables -C DOCKER-USER -o "$IFACE" -j ACCEPT 2>/dev/null \\
    || iptables -I DOCKER-USER 1 -o "$IFACE" -j ACCEPT
fi

if [[ -n "$SUBNET" ]]; then
  iptables -t nat -C POSTROUTING -s "$SUBNET" ! -o "$IFACE" -j MASQUERADE 2>/dev/null \\
    || iptables -t nat -A POSTROUTING -s "$SUBNET" ! -o "$IFACE" -j MASQUERADE
fi

iptables -t mangle -C FORWARD -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \\
  || iptables -t mangle -A FORWARD -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -C FORWARD -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \\
  || iptables -t mangle -A FORWARD -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null 2>&1 || true
for d in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 2 > "$d" 2>/dev/null || true; done

echo "FORWARD=$(iptables -S FORWARD | head -5 | tr '\\n' ';')"
echo "DOCKER_USER=$(iptables -S DOCKER-USER 2>/dev/null | head -10 | tr '\\n' ';' || echo none)"
echo "NAT=$(iptables -t nat -S POSTROUTING | tr '\\n' ';')"
"""
        try:
            result = host_exec.run(["bash", "-c", script], timeout=30.0)
            logger.info("iptables bypass: %s", result.stdout.strip())
        except host_exec.HostExecError as exc:
            raise FirewallError(
                f"Не удалось настроить iptables FORWARD/DOCKER-USER: {exc}"
            ) from exc

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
            logger.warning("Не удалось записать sysctl persist: %s", exc)

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
            host_exec.write_root_file(
                config.SYSCTL_FORWARD_PATH,
                (
                    "net.ipv4.ip_forward=1\n"
                    "net.ipv4.conf.all.rp_filter=2\n"
                    "net.ipv4.conf.default.rp_filter=2\n"
                ),
                mode=0o644,
            )
        except host_exec.HostExecError as exc:
            raise FirewallError(f"Не удалось включить ip_forward: {exc}") from exc
