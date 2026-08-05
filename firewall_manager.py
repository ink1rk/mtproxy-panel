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

        # WG NAT: PostUp/ensure_nat в Docker (при host net — это netns хоста).
        # Здесь только nft input для портов — без второго MASQUERADE в nft.
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


# ---------------------------------------------------------------------------
# WireGuard NAT/FORWARD — чистый Python, без shell-скриптов.
#
# Раньше это была bash-эвристика (heredoc, записанная как отдельный .sh файл
# в /usr/local/sbin с chmod +x — источник "Permission denied" и вообще лишней
# сущности, которую приходится отдельно поддерживать). Теперь каждое правило —
# отдельный host_exec.run(['iptables', ...]) вызов со списком аргументов:
# никакого shell-экранирования, никаких временных файлов, идемпотентно
# (проверка -C перед -I).
# ---------------------------------------------------------------------------
def _iptables_backends() -> list[str]:
    return [b for b in ("iptables", "iptables-nft", "iptables-legacy") if host_exec.which(b)]


def _ensure_rule(ipt: str, insert_args: list[str], check_args: list[str]) -> bool:
    """Вставляет правило, если его ещё нет. Возвращает True, если применилось."""
    if host_exec.run([ipt, *check_args], check=False).ok:
        return True
    return host_exec.run([ipt, *insert_args], check=False).ok


def ensure_wg_nat_forward(*, subnet: str, listen_port: int, wan: str) -> dict:
    """
    PostUp ровно как у проверенного годами рабочего wg-easy:
      - MASQUERADE (не SNAT на статичный IP — переживает смену DHCP-адреса)
      - FORWARD ACCEPT для wg0 (Docker ставит policy DROP)
      - DOCKER-USER ACCEPT для wg0, если цепочка есть
      - INPUT ACCEPT на UDP-порт WireGuard
    Применяется на все доступные бэкенды iptables (nft/legacy), т.к. Docker
    и хостовый alternatives иногда расходятся.
    """
    network_cidr = subnet if "/" in subnet else f"{subnet}/24"
    backends = _iptables_backends()
    for ipt in backends:
        host_exec.run([ipt, "-P", "FORWARD", "ACCEPT"], check=False)
        _ensure_rule(
            ipt, ["-I", "FORWARD", "1", "-i", "wg0", "-j", "ACCEPT"],
            ["-C", "FORWARD", "-i", "wg0", "-j", "ACCEPT"],
        )
        _ensure_rule(
            ipt, ["-I", "FORWARD", "1", "-o", "wg0", "-j", "ACCEPT"],
            ["-C", "FORWARD", "-o", "wg0", "-j", "ACCEPT"],
        )
        if host_exec.run([ipt, "-L", "DOCKER-USER", "-n"], check=False).ok:
            _ensure_rule(
                ipt, ["-I", "DOCKER-USER", "1", "-i", "wg0", "-j", "ACCEPT"],
                ["-C", "DOCKER-USER", "-i", "wg0", "-j", "ACCEPT"],
            )
            _ensure_rule(
                ipt, ["-I", "DOCKER-USER", "1", "-o", "wg0", "-j", "ACCEPT"],
                ["-C", "DOCKER-USER", "-o", "wg0", "-j", "ACCEPT"],
            )
        _ensure_rule(
            ipt,
            ["-t", "nat", "-I", "POSTROUTING", "1", "-s", network_cidr, "-o", wan, "-j", "MASQUERADE"],
            ["-t", "nat", "-C", "POSTROUTING", "-s", network_cidr, "-o", wan, "-j", "MASQUERADE"],
        )
        _ensure_rule(
            ipt,
            ["-I", "INPUT", "1", "-p", "udp", "-m", "udp", "--dport", str(listen_port), "-j", "ACCEPT"],
            ["-C", "INPUT", "-p", "udp", "-m", "udp", "--dport", str(listen_port), "-j", "ACCEPT"],
        )
    logger.info("WG NAT (Python): wan=%s port=%s backends=%s", wan, listen_port, backends)
    return {"wan": wan, "port": listen_port, "backends": backends}


def wg_nat_status(*, subnet: str, listen_port: int, wan: str) -> dict[str, bool]:
    """Для диагностики: что из правил реально применено сейчас."""
    network_cidr = subnet if "/" in subnet else f"{subnet}/24"
    ipt = "iptables"
    if not host_exec.which(ipt):
        backends = _iptables_backends()
        ipt = backends[0] if backends else "iptables"
    nat = host_exec.run(
        [ipt, "-t", "nat", "-C", "POSTROUTING", "-s", network_cidr, "-o", wan, "-j", "MASQUERADE"],
        check=False,
    ).ok
    forward_in = host_exec.run(
        [ipt, "-C", "FORWARD", "-i", "wg0", "-j", "ACCEPT"], check=False,
    ).ok
    forward_out = host_exec.run(
        [ipt, "-C", "FORWARD", "-o", "wg0", "-j", "ACCEPT"], check=False,
    ).ok
    input_accept = host_exec.run(
        [ipt, "-C", "INPUT", "-p", "udp", "-m", "udp", "--dport", str(listen_port), "-j", "ACCEPT"],
        check=False,
    ).ok
    docker_user_ok = True
    if host_exec.run([ipt, "-L", "DOCKER-USER", "-n"], check=False).ok:
        docker_user_ok = (
            host_exec.run([ipt, "-C", "DOCKER-USER", "-i", "wg0", "-j", "ACCEPT"], check=False).ok
            and host_exec.run([ipt, "-C", "DOCKER-USER", "-o", "wg0", "-j", "ACCEPT"], check=False).ok
        )
    return {
        "nat": nat,
        "forward": forward_in and forward_out,
        "docker_user": docker_user_ok,
        "input_accept": input_accept,
    }
