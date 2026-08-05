"""
WireGuard — native wg-quick@wg0 (systemd).

Почему не Docker на Timeweb/Ubuntu 26.04:
  - bridge DNAT ломался (нет цепочки DOCKER)
  - host/bridge давали handshake без интернета
  - AppArmor profile `wg` читает ключи ТОЛЬКО из /etc/wireguard/
  - Docker FORWARD/NAT + nft мешали return-path

Проверено на ams-1-vm-8cfh: native + PostUp wg-easy + DOCKER-USER
→ ping 1.1.1.1 из netns-клиента OK.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

import config
import host_exec
from firewall_manager import detect_wan_interface

logger = logging.getLogger(__name__)


class WireGuardError(RuntimeError):
    """Ошибка native WireGuard."""


WireGuardDockerError = WireGuardError  # совместимость импортов


class WireGuardManager:
    def __init__(self) -> None:
        host_exec.require_binaries("wg", "wg-quick", "ip", "iptables", "systemctl")
        Path("/etc/wireguard").mkdir(parents=True, exist_ok=True)
        try:
            Path("/etc/wireguard").chmod(0o700)
        except OSError:
            pass

    def _system_conf(self) -> Path:
        return Path("/etc/wireguard") / f"{config.WG_INTERFACE_NAME}.conf"

    def _panel_conf(self) -> Path:
        wg_confs = config.WG_CONFIG_DIR / "wg_confs"
        wg_confs.mkdir(parents=True, exist_ok=True)
        return wg_confs / f"{config.WG_INTERFACE_NAME}.conf"

    def get_status(self) -> str:
        result = host_exec.systemctl("is-active", config.WG_SYSTEMD_UNIT, check=False)
        state = (result.stdout or result.stderr).strip()
        if state == "active":
            show = host_exec.run(
                ["wg", "show", config.WG_INTERFACE_NAME], check=False,
            )
            return "running" if show.ok else "degraded"
        # fallback: iface up without unit
        link = host_exec.run(
            ["ip", "link", "show", "dev", config.WG_INTERFACE_NAME], check=False,
        )
        if link.ok:
            return "running"
        return state or "missing"

    def is_running(self) -> bool:
        return self.get_status() == "running"

    def _stop_docker_wg(self) -> None:
        """Убираем Docker WG (wg_server / wg-easy) — конфликт по :51820."""
        host_exec.run(["docker", "rm", "-f", config.WG_CONTAINER_NAME], check=False)
        host_exec.run(["docker", "rm", "-f", "wg-easy"], check=False)

    def _augment_postup(self, conf_text: str, *, wan: str, listen_port: int, subnet: str) -> str:
        """
        AppArmor profile `wg-quick` на Ubuntu разрешает только xtables-nft-multi /
        nft. Если iptables → legacy, PostUp с iptables падает с Permission denied
        и wg-quick откатывает интерфейс.

        Поэтому PostUp/PostDown в conf пустые — NAT/FORWARD ставит `_ensure_nat`
        из панели (unconfined).
        """
        del wan, listen_port, subnet  # NAT применяется отдельно
        lines: list[str] = []
        for line in conf_text.splitlines():
            if line.startswith("PostUp =") or line.startswith("PostDown ="):
                continue
            lines.append(line)
        return "\n".join(lines).rstrip() + "\n"

    def write_config(self, conf_text: str, *, listen_port: int, subnet: str) -> None:
        wan = detect_wan_interface()
        final = self._augment_postup(
            conf_text, wan=wan, listen_port=listen_port, subnet=subnet,
        )
        # AppArmor: /usr/bin/wg читает ключи только из /etc/wireguard/
        host_exec.write_root_file(str(self._system_conf()), final, mode=0o600)
        panel = self._panel_conf()
        panel.write_text(final, encoding="utf-8")
        try:
            panel.chmod(0o600)
        except OSError:
            pass
        logger.info("WG conf written wan=%s -> %s", wan, self._system_conf())

    def _ensure_sysctl(self) -> None:
        host_exec.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
        host_exec.run(
            ["sysctl", "-w", "net.ipv4.conf.all.src_valid_mark=1"], check=False,
        )
        try:
            host_exec.write_root_file(
                config.SYSCTL_FORWARD_PATH,
                "net.ipv4.ip_forward=1\nnet.ipv4.conf.all.src_valid_mark=1\n",
                mode=0o644,
            )
        except host_exec.HostExecError as exc:
            logger.warning("sysctl persist: %s", exc)

    def _ensure_nat(self, *, subnet: str, listen_port: int) -> None:
        wan = detect_wan_interface()
        network_cidr = subnet if "/" in subnet else f"{subnet}/24"
        # Публичный IP для SNAT (стабильнее MASQUERADE на некоторых VPS).
        src_ip = ""
        addr = host_exec.run(
            ["bash", "-c", f"ip -4 -o addr show dev {wan} | awk '{{print $4; exit}}'"],
            check=False,
        )
        if addr.ok and addr.stdout.strip():
            src_ip = addr.stdout.strip().split("/")[0]

        snat_line = (
            f"iptables -t nat -C POSTROUTING -s {network_cidr} -o {wan} "
            f"-j SNAT --to-source {src_ip} 2>/dev/null || "
            f"iptables -t nat -I POSTROUTING 1 -s {network_cidr} -o {wan} "
            f"-j SNAT --to-source {src_ip}"
            if src_ip
            else (
                f"iptables -t nat -C POSTROUTING -s {network_cidr} -o {wan} "
                f"-j MASQUERADE 2>/dev/null || "
                f"iptables -t nat -I POSTROUTING 1 -s {network_cidr} -o {wan} "
                f"-j MASQUERADE"
            )
        )

        script = f"""
set -e
iptables -P FORWARD ACCEPT 2>/dev/null || true
# До Docker-цепочек — иначе return-path иногда теряется.
iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o wg0 -j ACCEPT
if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  iptables -C DOCKER-USER -i wg0 -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -i wg0 -j ACCEPT
  iptables -C DOCKER-USER -o wg0 -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -o wg0 -j ACCEPT
fi
{snat_line}
iptables -C INPUT -p udp -m udp --dport {listen_port} -j ACCEPT 2>/dev/null \\
  || iptables -I INPUT 1 -p udp -m udp --dport {listen_port} -j ACCEPT
# ICMP туннеля (пинг 8.8.8.8 / gw)
iptables -C FORWARD -i wg0 -p icmp -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i wg0 -p icmp -j ACCEPT
iptables -C FORWARD -o wg0 -p icmp -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o wg0 -p icmp -j ACCEPT
# TCP MSS clamp — сайты при MTU 1280
iptables -t mangle -C FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \\
  || iptables -t mangle -A FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -C FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \\
  || iptables -t mangle -A FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
echo NAT_OK wan={wan} src={src_ip or 'masq'} port={listen_port}
"""
        # Persist helper for boot / docker restart
        helper = (
            "#!/bin/bash\nset -e\n"
            f"WG_SUBNET={network_cidr}\n"
            f"WG_PORT={listen_port}\n"
            + script
        )
        try:
            host_exec.write_root_file(config.WG_NAT_HELPER_PATH, helper, mode=0o755)
        except host_exec.HostExecError as exc:
            logger.warning("NAT helper persist: %s", exc)

        result = host_exec.run(["bash", "-c", script], check=False)
        if not result.ok:
            raise WireGuardError(f"NAT/FORWARD не применился: {result.output}")
        logger.info("WG NAT: %s", result.output)

    def _relax_apparmor(self) -> None:
        """
        Ubuntu AppArmor profiles wg / wg-quick ломают native WG:
        iptables-legacy exec denied, иногда `ip link set mtu` → Permission denied.
        Снимаем профили (идемпотентно).
        """
        script = r"""
set +e
mkdir -p /etc/apparmor.d/disable
for p in wg wg-quick; do
  src="/etc/apparmor.d/$p"
  if [ -f "$src" ] && [ ! -e "/etc/apparmor.d/disable/$p" ]; then
    ln -sf "$src" "/etc/apparmor.d/disable/$p"
  fi
  apparmor_parser -R "$src" 2>/dev/null || true
done
# iptables → nft: совместимее с Docker и AppArmor, если профиль вернётся
if [ -x /usr/sbin/iptables-nft ]; then
  update-alternatives --set iptables /usr/sbin/iptables-nft >/dev/null 2>&1 || true
  update-alternatives --set ip6tables /usr/sbin/ip6tables-nft >/dev/null 2>&1 || true
fi
echo APPARMOR_RELAXED
"""
        result = host_exec.run(["bash", "-c", script], check=False)
        logger.info("AppArmor WG: %s", result.output)

    def ensure_server_running(
        self,
        *,
        conf_text: str,
        listen_port: int,
        subnet: str,
        xray_port: int | None = None,  # noqa: ARG002
    ) -> None:
        self._relax_apparmor()
        self._stop_docker_wg()
        self._ensure_sysctl()
        self.write_config(conf_text, listen_port=listen_port, subnet=subnet)

        # поднять через systemd
        host_exec.systemctl("enable", config.WG_SYSTEMD_UNIT, check=False)
        if self.is_running():
            # sync peers без полного down/up
            sync = host_exec.run(
                [
                    "bash", "-c",
                    f"wg syncconf {config.WG_INTERFACE_NAME} "
                    f"<(wg-quick strip {self._system_conf()})",
                ],
                check=False,
            )
            if not sync.ok:
                logger.warning("syncconf failed (%s) — restart unit", sync.output)
                host_exec.systemctl("restart", config.WG_SYSTEMD_UNIT, check=False)
                time.sleep(1)
                if not self.is_running():
                    host_exec.run(["wg-quick", "down", config.WG_INTERFACE_NAME], check=False)
                    up = host_exec.run(
                        ["wg-quick", "up", config.WG_INTERFACE_NAME], check=False,
                    )
                    if not up.ok:
                        raise WireGuardError(f"wg-quick up failed: {up.output}")
        else:
            host_exec.run(["wg-quick", "down", config.WG_INTERFACE_NAME], check=False)
            host_exec.run(
                ["ip", "link", "delete", "dev", config.WG_INTERFACE_NAME],
                check=False,
            )
            host_exec.systemctl("reset-failed", config.WG_SYSTEMD_UNIT, check=False)
            # Сначала systemd — unit остаётся active; fallback на wg-quick up.
            started = host_exec.systemctl("start", config.WG_SYSTEMD_UNIT, check=False)
            time.sleep(0.5)
            if not self.is_running():
                up = host_exec.run(
                    ["wg-quick", "up", config.WG_INTERFACE_NAME], check=False,
                )
                if not up.ok and "already exists" not in up.output:
                    logger.warning("wg-quick up: %s (systemctl: %s)", up.output, started.output)
            if not self.is_running():
                raise WireGuardError(
                    "Не удалось поднять wg0. journalctl -u wg-quick@wg0"
                )
            host_exec.systemctl("reset-failed", config.WG_SYSTEMD_UNIT, check=False)

        self.wait_until_interface_ready()
        self._ensure_nat(subnet=subnet, listen_port=listen_port)

    def wait_until_interface_ready(self, timeout: float | None = None) -> None:
        if timeout is None:
            timeout = config.WG_INTERFACE_TIMEOUT_SECONDS
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            show = host_exec.run(
                ["wg", "show", config.WG_INTERFACE_NAME], check=False,
            )
            if show.ok:
                return
            last = show.output
            time.sleep(0.5)
        raise WireGuardError(f"wg0 не поднялся: {last}")

    def reload_config(self, *, conf_text: str, listen_port: int, subnet: str) -> None:
        if not self.is_running():
            self.ensure_server_running(
                conf_text=conf_text, listen_port=listen_port, subnet=subnet,
            )
            return
        self.write_config(conf_text, listen_port=listen_port, subnet=subnet)
        sync = host_exec.run(
            [
                "bash", "-c",
                f"wg syncconf {config.WG_INTERFACE_NAME} "
                f"<(wg-quick strip {self._system_conf()})",
            ],
            check=False,
        )
        if not sync.ok:
            logger.warning("syncconf failed — full ensure: %s", sync.output)
            self.ensure_server_running(
                conf_text=conf_text, listen_port=listen_port, subnet=subnet,
            )
            return
        self._ensure_nat(subnet=subnet, listen_port=listen_port)

    def _wg_dump(self, kind: str) -> str:
        result = host_exec.run(
            ["wg", "show", config.WG_INTERFACE_NAME, kind], check=False,
        )
        return result.stdout if result.ok else ""

    def get_peer_last_handshakes(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for line in self._wg_dump("latest-handshakes").splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                continue
        return result

    def get_peer_transfer_stats(self) -> dict[str, tuple[int, int]]:
        result: dict[str, tuple[int, int]] = {}
        for line in self._wg_dump("transfer").splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            try:
                result[parts[0]] = (int(parts[1]), int(parts[2]))
            except ValueError:
                continue
        return result

    def restart_server(self) -> None:
        host_exec.systemctl("restart", config.WG_SYSTEMD_UNIT, check=False)
        time.sleep(1)
        if not self.is_running():
            host_exec.run(["wg-quick", "down", config.WG_INTERFACE_NAME], check=False)
            up = host_exec.run(["wg-quick", "up", config.WG_INTERFACE_NAME], check=False)
            if not up.ok:
                raise WireGuardError(f"restart failed: {up.output}")
        self.wait_until_interface_ready()
        # NAT не в PostUp (AppArmor) — восстановить после рестарта iface
        server_conf = self._system_conf()
        subnet = config.WG_DEFAULT_SUBNET
        listen_port = config.WG_DEFAULT_PORT
        if server_conf.exists():
            text = server_conf.read_text(encoding="utf-8")
            for line in text.splitlines():
                if line.startswith("Address ="):
                    # Address = 10.8.0.1/24 → 10.8.0.0/24
                    addr = line.split("=", 1)[1].strip()
                    ip_part, _, prefix = addr.partition("/")
                    octets = ip_part.split(".")
                    if len(octets) == 4:
                        subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/{prefix or '24'}"
                elif line.startswith("ListenPort ="):
                    try:
                        listen_port = int(line.split("=", 1)[1].strip())
                    except ValueError:
                        pass
        self._ensure_nat(subnet=subnet, listen_port=listen_port)

    def remove_server(self) -> None:
        host_exec.systemctl("disable", "--now", config.WG_SYSTEMD_UNIT, check=False)
        host_exec.run(["wg-quick", "down", config.WG_INTERFACE_NAME], check=False)
        host_exec.run(
            ["ip", "link", "delete", "dev", config.WG_INTERFACE_NAME], check=False,
        )
        self._stop_docker_wg()
        try:
            self._system_conf().unlink(missing_ok=True)
        except OSError:
            pass
