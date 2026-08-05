"""
WireGuard — native wg-quick@wg0 (systemd).

Вся логика firewall/NAT — чистый Python (firewall_manager.py), без
bash-скриптов: ни heredoc, ни временных .sh файлов на диске, ни
process substitution. Каждая iptables-команда — отдельный
host_exec.run([...]) со списком аргументов.

PostUp/PostDown в самом wg0.conf не используются: AppArmor-профиль
`wg-quick` на Ubuntu 24.04+/26.04 может блокировать `iptables`/`ip link
set mtu` изнутри PostUp (см. _relax_apparmor). NAT/FORWARD применяются
отдельно, после поднятия интерфейса.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

import config
import host_exec
from firewall_manager import detect_wan_interface, ensure_wg_nat_forward

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

    def _syncconf(self) -> host_exec.CommandResult:
        """
        wg syncconf без bash process substitution: `wg-quick strip` в
        временный файл, затем `wg syncconf wg0 <файл>`. Чистый Python.
        """
        import tempfile

        strip = host_exec.run(
            ["wg-quick", "strip", str(self._system_conf())], check=False,
        )
        if not strip.ok:
            return strip
        fd, tmp_path = tempfile.mkstemp(prefix=".wg-stripped-")
        try:
            with open(fd, "w", encoding="utf-8") as handle:
                handle.write(strip.stdout)
            return host_exec.run(
                ["wg", "syncconf", config.WG_INTERFACE_NAME, tmp_path], check=False,
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)

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
        """
        PostUp ровно как у проверенного годами рабочего wg-easy (MASQUERADE,
        не SNAT на статичный IP). Единственное отличие: там WG живёт в
        отдельном netns контейнера (DOCKER-USER не нужен), у нас wg0 на
        хосте — Docker ставит FORWARD policy DROP, поэтому явный ACCEPT
        для wg0 обязателен. Реализация — чистый Python
        (firewall_manager.ensure_wg_nat_forward), без shell-скриптов.
        """
        wan = detect_wan_interface()
        ensure_wg_nat_forward(subnet=subnet, listen_port=listen_port, wan=wan)

    def _relax_apparmor(self) -> None:
        """
        Ubuntu AppArmor profiles wg / wg-quick ломают native WG:
        iptables-legacy exec denied, иногда `ip link set mtu` → Permission
        denied. Снимаем профили (идемпотентно). Чистый Python — никакого
        bash -c.
        """
        disable_dir = Path("/etc/apparmor.d/disable")
        try:
            disable_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("AppArmor disable dir: %s", exc)
        for profile in ("wg", "wg-quick"):
            src = Path(f"/etc/apparmor.d/{profile}")
            link = disable_dir / profile
            if src.exists() and not link.exists():
                try:
                    link.symlink_to(src)
                except OSError as exc:
                    logger.warning("AppArmor symlink %s: %s", profile, exc)
            host_exec.run(["apparmor_parser", "-R", str(src)], check=False)

        # iptables -> nft: совместимее с Docker, если профиль когда-то вернётся.
        nft_bin = Path("/usr/sbin/iptables-nft")
        if nft_bin.exists():
            host_exec.run(["update-alternatives", "--set", "iptables", str(nft_bin)], check=False)
        ip6_nft_bin = Path("/usr/sbin/ip6tables-nft")
        if ip6_nft_bin.exists():
            host_exec.run(["update-alternatives", "--set", "ip6tables", str(ip6_nft_bin)], check=False)
        logger.info("AppArmor WG profiles relaxed (Python)")

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
            sync = self._syncconf()
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
        sync = self._syncconf()
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
