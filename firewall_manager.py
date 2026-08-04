"""
nftables firewall для native VPN-стека панели.

Одна таблица `inet mtproxy-panel`:
- input: accept UDP WireGuard / TCP VLESS / TCP панели
- forward: accept трафик wg0
- postrouting: masquerade VPN-подсети (кроме выхода в wg0)

Идемпотентно: таблица пересоздаётся целиком при каждом ensure.
"""
from __future__ import annotations

import logging
import tempfile
from pathlib import Path

import config
import host_exec

logger = logging.getLogger(__name__)


class FirewallError(RuntimeError):
    """Ошибка применения nftables-правил."""


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
    """Управляет таблицей nftables панели."""

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
        """Применяет актуальную таблицу firewall/NAT."""
        panel = panel_port if panel_port is not None else config.APP_PORT
        table = _render_table(
            wg_port=wg_port,
            xray_port=xray_port,
            panel_port=panel,
            wg_subnet=wg_subnet,
            wg_iface=config.WG_INTERFACE_NAME,
        )
        # delete+recreate: flush оставляет пустую таблицу, а повторный
        # `table inet ... {` падает с "File exists".
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

        # Persist for reboot (best-effort).
        try:
            host_exec.write_root_file(config.NFT_RULES_PATH, table, mode=0o644)
        except host_exec.HostExecError as exc:
            logger.warning("Не удалось сохранить nftables ruleset: %s", exc)

        logger.info(
            "nftables %s: wg_port=%s xray_port=%s subnet=%s",
            config.NFT_TABLE_NAME, wg_port, xray_port, wg_subnet,
        )

    def clear_wireguard(self) -> None:
        """Убирает WG-правила, оставляя панель/Xray если есть."""
        # Полный flush таблицы — вызывающий код затем ensure() с актуальными портами.
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
                "net.ipv4.ip_forward=1\n",
                mode=0o644,
            )
        except host_exec.HostExecError as exc:
            raise FirewallError(f"Не удалось включить ip_forward: {exc}") from exc
