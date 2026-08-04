"""
Проверки после setup VPN-сервиса.
WireGuard — Docker (wg-easy style); Xray — native systemd.
"""
from __future__ import annotations

import logging
import socket
import urllib.request
from dataclasses import dataclass, field

import config
import host_exec

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


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


def _check_docker_running(name: str) -> CheckResult:
    result = host_exec.run(
        ["docker", "inspect", "-f", "{{.State.Status}}", name],
        check=False,
    )
    status = (result.stdout or "").strip()
    return CheckResult(
        name="service active",
        ok=status == "running",
        detail=f"docker {name} -> {status or 'missing'}",
    )


def _check_systemd_active(unit: str) -> CheckResult:
    result = host_exec.systemctl("is-active", unit, check=False)
    state = (result.stdout or result.stderr).strip()
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


def _check_wg_inside(subnet: str) -> CheckResult:
    show = host_exec.run(
        ["docker", "exec", config.WG_CONTAINER_NAME, "wg", "show"],
        check=False,
    )
    nat = host_exec.run(
        ["docker", "exec", config.WG_CONTAINER_NAME, "iptables", "-t", "nat", "-S", "POSTROUTING"],
        check=False,
    )
    fwd = host_exec.run(
        ["docker", "exec", config.WG_CONTAINER_NAME, "iptables", "-S", "FORWARD"],
        check=False,
    )
    has_iface = show.ok and "interface:" in show.stdout
    has_masq = nat.ok and "MASQUERADE" in nat.stdout and "eth0" in nat.stdout
    has_fwd = fwd.ok and "-i wg0" in fwd.stdout
    ok = has_iface and has_masq and has_fwd
    detail = (
        f"wg0={'yes' if has_iface else 'NO'} "
        f"masq_eth0={'yes' if has_masq else 'NO'} "
        f"fwd={'yes' if has_fwd else 'NO'} subnet={subnet}"
    )
    return CheckResult(name="routing/nat", ok=ok, detail=detail)


def _check_external_connectivity() -> CheckResult:
    last_err = ""
    for url in config.PUBLIC_IP_LOOKUP_URLS:
        try:
            with urllib.request.urlopen(url, timeout=config.PUBLIC_IP_LOOKUP_TIMEOUT_SECONDS) as resp:
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
    report.checks.append(_check_docker_running(config.WG_CONTAINER_NAME))
    report.checks.append(_check_port(listen_port, "udp"))
    report.checks.append(_check_wg_inside(subnet))
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
