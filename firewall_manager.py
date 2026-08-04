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

        # WireGuard NAT живёт ВНУТРИ Docker-контейнера (как wg-easy).
        # На хосте только открываем порты в nft input — без host MASQUERADE.
        logger.info(
            "firewall input ready: wg_port=%s xray_port=%s",
            wg_port, xray_port,
        )

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
