"""
Native Xray: бинарник + systemd unit xray.service.

Конфиг: /usr/local/etc/xray/config.json (и зеркало в data/xray/).
Список клиентов применяется перезаписью config.json + restart unit.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import config
import host_exec
import utils
from firewall_manager import FirewallError, FirewallManager

logger = logging.getLogger(__name__)


class XrayError(RuntimeError):
    """Ошибка native Xray-сервера."""


XrayDockerError = XrayError


class XrayManager:
    """Управляет native Xray через systemd."""

    def __init__(self) -> None:
        binary = config.XRAY_BINARY_PATH
        if not Path(binary).exists() and host_exec.which("xray") is None:
            raise XrayError(
                f"Xray не установлен ({binary} не найден). Запустите bash install.sh"
            )
        try:
            host_exec.require_binaries("systemctl", "nft")
            self._firewall = FirewallManager()
        except (host_exec.HostExecError, FirewallError) as exc:
            raise XrayError(str(exc)) from exc
        self._unit = config.XRAY_SYSTEMD_UNIT
        self._binary = binary if Path(binary).exists() else "xray"

    def is_running(self) -> bool:
        return self.get_status() == "running"

    def get_status(self) -> str:
        conf = Path(config.XRAY_SYSTEM_CONF_PATH)
        if not conf.exists() and not self._unit_loaded():
            return "missing"
        result = host_exec.systemctl("is-active", self._unit, check=False)
        state = (result.stdout or result.stderr).strip()
        if state == "active":
            return "running"
        if state == "failed":
            return "failed"
        if state in {"inactive", "dead"}:
            return "stopped"
        return state or "stopped"

    def _unit_loaded(self) -> bool:
        result = host_exec.systemctl("cat", self._unit, check=False)
        return result.ok

    def write_config(self, config_json: dict) -> None:
        text = json.dumps(config_json, indent=2, ensure_ascii=False) + "\n"
        # Валидация до записи в /usr/local/etc
        self._validate_config(text)
        host_exec.write_root_file(config.XRAY_SYSTEM_CONF_PATH, text, mode=0o644)
        mirror = config.XRAY_CONFIG_DIR / "config.json"
        mirror.parent.mkdir(parents=True, exist_ok=True)
        mirror.write_text(text, encoding="utf-8")

    def _validate_config(self, text: str) -> None:
        import os
        import tempfile

        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as handle:
            handle.write(text)
            tmp = handle.name
        try:
            os.chmod(tmp, 0o644)
            result = host_exec.run(
                [self._binary, "run", "-test", "-c", tmp],
                check=False,
                timeout=20.0,
            )
            if not result.ok:
                raise XrayError(
                    f"config.json не прошёл проверку xray -test: {result.output}"
                )
        finally:
            Path(tmp).unlink(missing_ok=True)

    def ensure_server_running(
        self,
        listen_port: int,
        config_json: dict,
        *,
        wg_port: int | None = None,
        wg_subnet: str | None = None,
    ) -> None:
        self.write_config(config_json)
        self._ensure_systemd_unit()
        try:
            self._firewall.ensure(
                wg_port=wg_port,
                xray_port=listen_port,
                wg_subnet=wg_subnet,
            )
        except FirewallError as exc:
            raise XrayError(str(exc)) from exc

        try:
            host_exec.systemctl("enable", self._unit)
            host_exec.systemctl("restart", self._unit)
        except host_exec.HostExecError as exc:
            logs = "\n".join(host_exec.journalctl_unit(self._unit, lines=40))
            raise XrayError(f"Не удалось запустить {self._unit}: {exc}\n{logs}") from exc

        self._wait_running(listen_port)

    def apply_config(
        self,
        config_json: dict,
        *,
        listen_port: int | None = None,
        wg_port: int | None = None,
        wg_subnet: str | None = None,
    ) -> None:
        self.write_config(config_json)
        if listen_port is not None:
            try:
                self._firewall.ensure(
                    wg_port=wg_port,
                    xray_port=listen_port,
                    wg_subnet=wg_subnet,
                )
            except FirewallError as exc:
                raise XrayError(str(exc)) from exc
        try:
            host_exec.systemctl("restart", self._unit)
        except host_exec.HostExecError as exc:
            raise XrayError(f"Не удалось перезапустить Xray: {exc}") from exc
        self._wait_running(listen_port)
        logger.info("Конфигурация Xray применена (restart %s)", self._unit)

    def _ensure_systemd_unit(self) -> None:
        """Гарантирует unit-файл, указывающий на наш config path."""
        unit_path = Path(config.XRAY_SYSTEMD_UNIT_PATH)
        desired = f"""[Unit]
Description=Xray Service (VLESS+REALITY, managed by mtproxy-panel)
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={self._binary} run -c {config.XRAY_SYSTEM_CONF_PATH}
Restart=on-failure
RestartSec=3
LimitNOFILE=1000000
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""
        current = ""
        if unit_path.exists():
            try:
                current = unit_path.read_text(encoding="utf-8")
            except OSError:
                current = ""
        if config.XRAY_SYSTEM_CONF_PATH not in current or self._binary not in current:
            host_exec.write_root_file(str(unit_path), desired, mode=0o644)
            host_exec.systemctl("daemon-reload")

    def _wait_running(self, listen_port: int | None = None) -> None:
        """
        systemd 'active' для Type=simple означает лишь что процесс форкнулся —
        сокет может забиндиться на 100-300мс позже (особенно первый запуск,
        когда Xray ещё генерирует внутренние структуры REALITY). Если health
        check запускается сразу после этого, порт иногда ещё не слушает,
        setup_server() считает это ошибкой и откатывает только что поднятый
        сервер. Поэтому здесь же дожидаемся реального accept() на порту.
        """
        deadline = time.monotonic() + config.XRAY_START_TIMEOUT_SECONDS
        became_active = False
        while time.monotonic() < deadline:
            status = self.get_status()
            if status == "running":
                became_active = True
                if listen_port is None:
                    return
                if utils.check_tcp_port_open("127.0.0.1", listen_port, timeout=3.0):
                    return
            if status == "failed":
                logs = "\n".join(host_exec.journalctl_unit(self._unit, lines=40))
                raise XrayError(f"{self._unit} упал:\n{logs}")
            time.sleep(0.4)
        logs = "\n".join(host_exec.journalctl_unit(self._unit, lines=40))
        if became_active:
            raise XrayError(
                f"{self._unit} активен, но порт {listen_port} не открылся за "
                f"{config.XRAY_START_TIMEOUT_SECONDS:.0f}с\n{logs}"
            )
        raise XrayError(
            f"{self._unit} не стал active за {config.XRAY_START_TIMEOUT_SECONDS:.0f}с\n{logs}"
        )

    def restart_server(self) -> None:
        try:
            host_exec.systemctl("restart", self._unit)
        except host_exec.HostExecError as exc:
            raise XrayError(f"Не удалось перезапустить Xray: {exc}") from exc
        self._wait_running()

    def remove_server(self) -> None:
        host_exec.systemctl("disable", "--now", self._unit, check=False)
        host_exec.remove_root_file(config.XRAY_SYSTEM_CONF_PATH)
        try:
            self._firewall.ensure(wg_port=None, xray_port=None, wg_subnet=None)
        except FirewallError as exc:
            logger.warning("Не удалось обновить nftables после сброса Xray: %s", exc)
