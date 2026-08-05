"""
Проверки после setup VPN-сервиса.
WireGuard — native wg-quick; Xray — native systemd.
"""
from __future__ import annotations

import logging
import socket
import urllib.request
from dataclasses import dataclass, field

import config
import host_exec
from firewall_manager import detect_wan_interface, tunnel_nat_status

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ClientDiagnosis:
    """
    Диагноз одного клиента по счётчикам активности/трафика. Сейчас
    заполняется для WireGuard (handshake/transfer); структура намеренно
    протокол-независима, чтобы её мог использовать любой провайдер
    (см. providers/base.py), у которого есть понятие "клиент подключался
    настолько недавно" и "сколько байт передано".
    """

    name: str
    has_handshake: bool
    handshake_age_seconds: int | None
    rx_bytes: int
    tx_bytes: int
    verdict: str
    severity: str  # "ok" | "warning" | "error"


@dataclass
class HealthReport:
    service: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    def format(self) -> str:
        lines = [f"[{self.service}] health: {'OK' if self.ok else 'FAIL'}"]
        for check in self.checks:
            mark = "OK" if check.ok else "FAIL"
            lines.append(f"  [{mark}] {check.name}: {check.detail}")
        return "\n".join(lines)


def _check_systemd_active(unit: str) -> CheckResult:
    result = host_exec.systemctl("is-active", unit, check=False)
    state = (result.stdout or result.stderr).strip()
    # wg0 may be up via wg-quick without unit "active" briefly
    if state != "active" and unit == config.WG_SYSTEMD_UNIT:
        show = host_exec.run(["wg", "show", config.WG_INTERFACE_NAME], check=False)
        if show.ok:
            return CheckResult(
                name="service active",
                ok=True,
                detail=f"{unit} -> {state or 'unknown'} (wg0 up)",
            )
    return CheckResult(
        name="service active",
        ok=state == "active",
        detail=f"{unit} -> {state or 'unknown'}",
    )


def _port_listening(port: int, proto: str) -> bool:
    flag = "-ulnp" if proto == "udp" else "-tlnp"
    result = host_exec.run(["ss", flag], check=False)
    needle = f":{port}"
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        if parts[3].endswith(needle) or parts[3].endswith(f"]:{port}"):
            return True
    if proto == "tcp":
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            return False
    return False


def _check_port(port: int, proto: str) -> CheckResult:
    ok = _port_listening(port, proto)
    return CheckResult(
        name="port listening",
        ok=ok,
        detail=f"{proto.upper()} {port} {'LISTEN' if ok else 'NOT LISTENING'}",
    )


def _check_wg_native(subnet: str, listen_port: int) -> CheckResult:
    wan = detect_wan_interface()
    show = host_exec.run(["wg", "show", config.WG_INTERFACE_NAME], check=False)
    nat = host_exec.run(["iptables", "-t", "nat", "-S", "POSTROUTING"], check=False)
    fwd = host_exec.run(["iptables", "-S", "FORWARD"], check=False)
    docker_user = host_exec.run(["iptables", "-S", "DOCKER-USER"], check=False)
    has_iface = show.ok and "interface:" in show.stdout
    subnet_base = subnet.split("/")[0].rsplit(".", 1)[0]
    nat_out = nat.stdout if nat.ok else ""
    has_nat = subnet_base in nat_out and (
        "MASQUERADE" in nat_out or "SNAT" in nat_out or "--to-source" in nat_out
    )
    has_fwd = fwd.ok and "-i wg0" in fwd.stdout and "-o wg0" in fwd.stdout
    has_du = (not docker_user.ok) or (
        "-i wg0" in docker_user.stdout and "-o wg0" in docker_user.stdout
    )
    ok = has_iface and has_nat and has_fwd
    detail = (
        f"wg0={'yes' if has_iface else 'NO'} "
        f"nat={'yes' if has_nat else 'NO'} "
        f"fwd={'yes' if has_fwd else 'NO'} "
        f"docker-user={'yes' if has_du else 'NO'} "
        f"wan={wan} subnet={subnet} udp={listen_port}"
    )
    return CheckResult(name="routing/nat", ok=ok, detail=detail)


def _check_external_connectivity() -> CheckResult:
    last_err = ""
    for url in config.PUBLIC_IP_LOOKUP_URLS:
        try:
            with urllib.request.urlopen(
                url, timeout=config.PUBLIC_IP_LOOKUP_TIMEOUT_SECONDS
            ) as resp:
                body = resp.read().decode("utf-8", "replace").strip()
                if body:
                    return CheckResult(
                        name="external connectivity",
                        ok=True,
                        detail=f"egress OK -> {body}",
                    )
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
    return CheckResult(
        name="external connectivity",
        ok=False,
        detail=f"host egress fail: {last_err or 'unknown'}",
    )


def check_wireguard(*, listen_port: int, subnet: str) -> HealthReport:
    report = HealthReport(service="wireguard")
    report.checks.append(_check_systemd_active(config.WG_SYSTEMD_UNIT))
    report.checks.append(_check_port(listen_port, "udp"))
    report.checks.append(_check_wg_native(subnet, listen_port))
    report.checks.append(_check_external_connectivity())
    if not report.ok:
        logger.error("%s", report.format())
    else:
        logger.info("%s", report.format())
    return report


def check_xray(*, listen_port: int) -> HealthReport:
    report = HealthReport(service="xray")
    report.checks.append(_check_systemd_active(config.XRAY_SYSTEMD_UNIT))
    report.checks.append(_check_port(listen_port, "tcp"))
    route = host_exec.run(["ip", "-4", "route", "show", "default"], check=False)
    report.checks.append(
        CheckResult(
            name="routing",
            ok=route.ok and bool(route.stdout.strip()),
            detail=f"default route={'yes' if route.stdout.strip() else 'NO'}",
        )
    )
    report.checks.append(_check_external_connectivity())
    if not report.ok:
        logger.error("%s", report.format())
    else:
        logger.info("%s", report.format())
    return report


# ---------------------------------------------------------------------------
# Диагностика "handshake есть, интернета нет" — самая частая жалоба.
# Отвечает не только "OK/FAIL", но и человекочитаемым выводом с причиной,
# чтобы не гонять руками wg show / iptables каждый раз.
# ---------------------------------------------------------------------------
def get_wg0_mtu() -> int | None:
    result = host_exec.run(["ip", "-o", "link", "show", "dev", "wg0"], check=False)
    if not result.ok:
        return None
    parts = result.stdout.split()
    if "mtu" in parts:
        idx = parts.index("mtu")
        if idx + 1 < len(parts):
            try:
                return int(parts[idx + 1])
            except ValueError:
                return None
    return None


def diagnose_wireguard_routing(*, subnet: str, listen_port: int) -> HealthReport:
    """Та же информация, что check_wireguard, но с MTU и без внешнего egress-запроса."""
    wan = detect_wan_interface()
    report = HealthReport(service="wireguard-routing")
    report.checks.append(_check_systemd_active(config.WG_SYSTEMD_UNIT))
    report.checks.append(_check_port(listen_port, "udp"))
    status = tunnel_nat_status(
        interface=config.WG_INTERFACE_NAME, subnet=subnet, listen_port=listen_port, wan=wan,
    )
    report.checks.append(CheckResult("NAT (MASQUERADE)", status["nat"], f"wan={wan}"))
    report.checks.append(CheckResult("FORWARD accept для wg0", status["forward"], ""))
    report.checks.append(CheckResult("DOCKER-USER accept для wg0", status["docker_user"], ""))
    report.checks.append(CheckResult("INPUT accept UDP-порта", status["input_accept"], f"port={listen_port}"))
    mtu = get_wg0_mtu()
    report.checks.append(CheckResult("MTU интерфейса", mtu is not None, f"{mtu if mtu else 'н/д'}"))
    return report


def diagnose_client(
    *, name: str, handshake_epoch: int, rx_bytes: int, tx_bytes: int,
) -> ClientDiagnosis:
    """
    Человекочитаемый вердикт по одному клиенту на основе handshake/трафика.
    Главная цель — отличить "конфиг сервера сломан" от "проблема на стороне
    клиента/сети" без часов ручного разбора логов.
    """
    import time

    has_handshake = handshake_epoch > 0
    age = int(time.time()) - handshake_epoch if has_handshake else None

    if not has_handshake:
        return ClientDiagnosis(
            name=name, has_handshake=False, handshake_age_seconds=None,
            rx_bytes=rx_bytes, tx_bytes=tx_bytes, severity="error",
            verdict=(
                "Клиент ни разу не подключался. Проверь: скачан ли АКТУАЛЬНЫЙ "
                "QR/конфиг (ключи меняются при пересоздании устройства или "
                "сброса сервера), верный ли Endpoint:порт, не блокирует ли "
                "сеть клиента этот UDP-порт."
            ),
        )

    # handshake есть, но получено мало, а сервер продолжает слать (keepalive
    # вхолостую) — классический "подключился, интернета нет".
    if rx_bytes < 2048 and tx_bytes > max(rx_bytes, 512) * 2:
        return ClientDiagnosis(
            name=name, has_handshake=True, handshake_age_seconds=age,
            rx_bytes=rx_bytes, tx_bytes=tx_bytes, severity="warning",
            verdict=(
                f"Handshake прошёл, но реальный трафик от клиента почти не "
                f"идёт (получено ~{rx_bytes} Б, сервер шлёт keepalive "
                f"вхолостую). Маршрутизация/NAT сервера тут ни при чём — "
                f"смотри на стороне клиента: другой активный VPN/антивирус с "
                f"сетевым фильтром (Kerio, Cisco AnyConnect и т.п.), "
                f"провайдер/DPI, ограничения самой сети до этого сервера."
            ),
        )

    if rx_bytes >= 2048:
        return ClientDiagnosis(
            name=name, has_handshake=True, handshake_age_seconds=age,
            rx_bytes=rx_bytes, tx_bytes=tx_bytes, severity="ok",
            verdict="Трафик идёт нормально.",
        )

    return ClientDiagnosis(
        name=name, has_handshake=True, handshake_age_seconds=age,
        rx_bytes=rx_bytes, tx_bytes=tx_bytes, severity="warning",
        verdict="Недостаточно данных для вывода — подключись и подожди немного, затем обнови страницу.",
    )
