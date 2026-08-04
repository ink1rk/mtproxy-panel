"""
Native WireGuard: wireguard-tools + systemd wg-quick@wg0.

Конфиг: /etc/wireguard/wg0.conf
NAT/firewall: nftables (firewall_manager)
Горячее обновление peer-ов: wg syncconf
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

import config
import host_exec
from firewall_manager import FirewallError, FirewallManager

logger = logging.getLogger(__name__)


class WireGuardError(RuntimeError):
    """Ошибка native WireGuard-сервера."""


# Обратная совместимость имён (старые catch в коде/логах).
WireGuardDockerError = WireGuardError


class WireGuardManager:
    """Управляет native WireGuard через wg-quick systemd unit."""

    def __init__(self) -> None:
        try:
            host_exec.require_binaries("wg", "wg-quick", "systemctl", "nft")
            self._firewall = FirewallManager()
        except (host_exec.HostExecError, FirewallError) as exc:
            raise WireGuardError(str(exc)) from exc
        self._unit = config.WG_SYSTEMD_UNIT

    def is_running(self) -> bool:
        return self.get_status() == "running"

    def get_status(self) -> str:
        conf = Path(config.WG_SYSTEM_CONF_PATH)
        if not conf.exists() and not self._unit_exists():
            return "missing"
        result = host_exec.systemctl("is-active", self._unit, check=False)
        state = (result.stdout or result.stderr).strip()
        if state == "active":
            return "running"
        if state in {"failed"}:
            return "failed"
        if state in {"inactive", "dead"}:
            return "stopped"
        return state or "stopped"

    def _unit_exists(self) -> bool:
        result = host_exec.systemctl("cat", self._unit, check=False)
        return result.ok

    def write_config(self, conf_text: str) -> None:
        host_exec.write_root_file(config.WG_SYSTEM_CONF_PATH, conf_text, mode=0o600)
        # Зеркало в data/ для бэкапа/диагностики (не источник истины для wg-quick).
        mirror_dir = config.WG_CONFIG_DIR / "wg_confs"
        mirror_dir.mkdir(parents=True, exist_ok=True)
        (mirror_dir / f"{config.WG_INTERFACE_NAME}.conf").write_text(conf_text, encoding="utf-8")

    def ensure_server_running(
        self,
        *,
        conf_text: str,
        listen_port: int,
        subnet: str,
        xray_port: int | None = None,
    ) -> None:
        """Пишет конфиг без PostUp, поднимает wg-quick@wg0, затем применяет NAT."""
        # Убираем опасный PostUp на внешний .sh (Permission denied → rollback wg0).
        conf_text = self._strip_post_hooks(conf_text)
        self.write_config(conf_text)

        try:
            self._firewall.ensure_ip_forward()
        except FirewallError as exc:
            raise WireGuardError(str(exc)) from exc

        try:
            host_exec.systemctl("enable", self._unit)
            host_exec.systemctl("restart", self._unit)
        except host_exec.HostExecError as exc:
            logs = "\n".join(host_exec.journalctl_unit(self._unit, lines=40))
            raise WireGuardError(
                f"Не удалось запустить {self._unit}: {exc}\n{logs}"
            ) from exc

        self.wait_until_interface_ready()

        # NAT только ПОСЛЕ успешного подъёма интерфейса (не из PostUp).
        try:
            self._firewall.ensure(
                wg_port=listen_port,
                xray_port=xray_port,
                wg_subnet=subnet if "/" in subnet else f"{subnet}/24",
            )
        except FirewallError as exc:
            raise WireGuardError(str(exc)) from exc

    @staticmethod
    def _strip_post_hooks(conf_text: str) -> str:
        lines = [
            line for line in conf_text.splitlines()
            if not line.startswith("PostUp ")
            and not line.startswith("PostUp=")
            and not line.startswith("PostDown ")
            and not line.startswith("PostDown=")
        ]
        return "\n".join(lines).rstrip() + "\n"

    def wait_until_interface_ready(self, timeout: float | None = None) -> None:
        if timeout is None:
            timeout = config.WG_INTERFACE_TIMEOUT_SECONDS
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            if self.get_status() == "failed":
                logs = "\n".join(host_exec.journalctl_unit(self._unit, lines=40))
                raise WireGuardError(f"{self._unit} в состоянии failed:\n{logs}")
            result = host_exec.run(
                ["wg", "show", config.WG_INTERFACE_NAME],
                check=False,
            )
            if result.ok:
                return
            last = result.output
            time.sleep(0.5)
        raise WireGuardError(
            f"Интерфейс {config.WG_INTERFACE_NAME} не поднялся за {timeout:.0f}с. "
            f"wg: {last or '(пусто)'}"
        )

    def reload_config(self, *, conf_text: str, listen_port: int, subnet: str) -> None:
        """Горячее применение peer-ов через wg syncconf + обновление NAT."""
        conf_text = self._strip_post_hooks(conf_text)
        self.write_config(conf_text)

        if not self.is_running():
            self.ensure_server_running(
                conf_text=conf_text, listen_port=listen_port, subnet=subnet,
            )
            return

        strip = host_exec.run(
            ["wg-quick", "strip", config.WG_SYSTEM_CONF_PATH],
            check=True,
        )
        try:
            host_exec.run(
                ["wg", "syncconf", config.WG_INTERFACE_NAME, "/dev/stdin"],
                input_text=strip.stdout,
            )
        except host_exec.HostExecError as exc:
            logger.warning("wg syncconf не удался (%s) — полный restart", exc)
            host_exec.systemctl("restart", self._unit)
            self.wait_until_interface_ready()
        logger.info("Конфигурация WireGuard применена (wg syncconf)")

    def get_peer_last_handshakes(self) -> dict[str, int]:
        result = host_exec.run(
            ["wg", "show", config.WG_INTERFACE_NAME, "latest-handshakes"],
            check=False,
        )
        if not result.ok:
            return {}
        out: dict[str, int] = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                continue
        return out

    def get_peer_transfer_stats(self) -> dict[str, tuple[int, int]]:
        result = host_exec.run(
            ["wg", "show", config.WG_INTERFACE_NAME, "transfer"],
            check=False,
        )
        if not result.ok:
            return {}
        out: dict[str, tuple[int, int]] = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            try:
                out[parts[0]] = (int(parts[1]), int(parts[2]))
            except ValueError:
                continue
        return out

    def restart_server(self) -> None:
        try:
            host_exec.systemctl("restart", self._unit)
        except host_exec.HostExecError as exc:
            raise WireGuardError(f"Не удалось перезапустить WireGuard: {exc}") from exc
        self.wait_until_interface_ready()

    def remove_server(self) -> None:
        host_exec.systemctl("disable", "--now", self._unit, check=False)
        # На случай если unit не остановил интерфейс.
        host_exec.run(
            ["wg-quick", "down", config.WG_SYSTEM_CONF_PATH],
            check=False,
        )
        host_exec.remove_root_file(config.WG_SYSTEM_CONF_PATH)
        try:
            self._firewall.clear_wireguard()
            self._firewall.ensure(wg_port=None, xray_port=None, wg_subnet=None)
        except FirewallError as exc:
            logger.warning("Не удалось обновить nftables после сброса WG: %s", exc)
