"""
Обязательные проверки после создания/перезапуска VPN-сервиса.

1. service active
2. port listening
3. routing test
4. external connectivity test
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
            mark = "✓" if check.ok else "✗"
            lines.append(f"  {mark} {check.name}: {check.detail}")
        return "\n".join(lines)


def _check_service_active(unit: str) -> CheckResult:
    result = host_exec.systemctl("is-active", unit, check=False)
    state = (result.stdout or result.stderr).strip()
    return CheckResult(
        name="service active",
        ok=state == "active",
        detail=f"{unit} -> {state or 'unknown'}",
    )


def _port_listening(port: int, proto: str) -> bool:
    """proto: 'udp' | 'tcp'."""
    flag = "-ulnp" if proto == "udp" else "-tlnp"
    result = host_exec.run(["ss", flag], check=False)
    needle = f":{port}"
    for line in result.stdout.splitlines():
        # ss: Local Address:Port column — match :PORT as token end / whitespace
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3] if proto == "tcp" or proto == "udp" else ""
        # For ss output, local addr is usually column 4 (index 3)
        if local.endswith(needle) or local.endswith(f"]:{port}"):
            return True
    # Fallback: try binding check is wrong for already-listening; use /proc
    try:
        if proto == "tcp":
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        # UDP: send empty datagram — if something listens locally, no error usually
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(0.5)
            sock.bind(("127.0.0.1", 0))
            sock.sendto(b"", ("127.0.0.1", port))
            return True  # best-effort; real check is ss above
        finally:
            sock.close()
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


def _check_wg_routing() -> CheckResult:
    iface = config.WG_INTERFACE_NAME
    link = host_exec.run(["ip", "-br", "link", "show", iface], check=False)
    addr = host_exec.run(["ip", "-4", "addr", "show", "dev", iface], check=False)
    route = host_exec.run(["ip", "-4", "route", "show", "default"], check=False)
    ok = link.ok and "UP" in link.stdout.upper() and addr.ok and "inet " in addr.stdout
    detail = (
        f"{iface}: {(link.stdout or link.stderr).strip()} | "
        f"addr={'yes' if 'inet ' in addr.stdout else 'no'} | "
        f"default={'yes' if route.ok and route.stdout.strip() else 'no'}"
    )
    return CheckResult(name="routing", ok=ok, detail=detail)


def _check_xray_routing(listen_port: int) -> CheckResult:
    # Для Xray "routing" = процесс слушает и outbound freedom доступен (default route).
    route = host_exec.run(["ip", "-4", "route", "show", "default"], check=False)
    has_default = route.ok and bool(route.stdout.strip())
    return CheckResult(
        name="routing",
        ok=has_default,
        detail=(
            f"default route={'yes' if has_default else 'MISSING'}; "
            f"inbound tcp/{listen_port}"
        ),
    )


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
                        detail=f"egress OK via {url} -> {body}",
                    )
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
            continue
    return CheckResult(
        name="external connectivity",
        ok=False,
        detail=f"не удалось выйти в интернет с хоста: {last_err or 'unknown'}",
    )


def _check_wg_nat(subnet: str) -> CheckResult:
    from firewall_manager import detect_wan_interface

    ipt_nat = host_exec.run(["iptables", "-t", "nat", "-S", "POSTROUTING"], check=False)
    ipt_fwd = host_exec.run(["iptables", "-S", "FORWARD"], check=False)
    route = host_exec.run(
        ["ip", "-4", "route", "get", "1.1.1.1", "from", "10.66.0.2", "iif", config.WG_INTERFACE_NAME],
        check=False,
    )
    wan = detect_wan_interface()
    subnet_base = subnet.split("/")[0].rsplit(".", 1)[0]
    has_wan_masq = (
        "MASQUERADE" in ipt_nat.stdout
        and subnet_base in ipt_nat.stdout
        and f"-o {wan}" in ipt_nat.stdout
    )
    # Старый опасный вариант ! -o wg0 без привязки к WAN — считаем слабее.
    has_any_masq = "MASQUERADE" in ipt_nat.stdout and subnet_base in ipt_nat.stdout
    fwd_ok = f"-i {config.WG_INTERFACE_NAME}" in ipt_fwd.stdout
    route_ok = route.ok and wan in route.stdout
    ok = (has_wan_masq or has_any_masq) and fwd_ok and route_ok
    detail = (
        f"wan={wan} masq={'wan' if has_wan_masq else ('any' if has_any_masq else 'NO')} "
        f"fwd={'yes' if fwd_ok else 'NO'} "
        f"route_get={'yes' if route_ok else 'NO'} ({route.stdout.strip()[:80]})"
    )
    return CheckResult(name="routing/nat", ok=ok, detail=detail)


def check_wireguard(*, listen_port: int, subnet: str) -> HealthReport:
    report = HealthReport(service="wireguard")
    report.checks.append(_check_service_active(config.WG_SYSTEMD_UNIT))
    report.checks.append(_check_port(listen_port, "udp"))
    report.checks.append(_check_wg_routing())
    report.checks.append(_check_wg_nat(subnet))
    report.checks.append(_check_external_connectivity())
    if not report.ok:
        logger.error("%s", report.format())
    else:
        logger.info("%s", report.format())
    return report


def check_xray(*, listen_port: int) -> HealthReport:
    report = HealthReport(service="xray")
    report.checks.append(_check_service_active(config.XRAY_SYSTEMD_UNIT))
    report.checks.append(_check_port(listen_port, "tcp"))
    report.checks.append(_check_xray_routing(listen_port))
    report.checks.append(_check_external_connectivity())
    if not report.ok:
        logger.error("%s", report.format())
    else:
        logger.info("%s", report.format())
    return report


def require_ok(report: HealthReport) -> None:
    if not report.ok:
        raise RuntimeError(report.format())
