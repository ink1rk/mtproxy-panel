"""
WireGuard в Docker — та же схема, что у wg-easy (weejewel / wg-easy):

  - bridge network + published UDP port
  - NET_ADMIN + ip_forward + src_valid_mark
  - PostUp MASQUERADE -o eth0 ВНУТРИ контейнера
  - наш wg0.conf (без PEERS= у linuxserver)

Native wg-quick@wg0 на хосте отключается: он конфликтовал с Docker/nft
и давал handshake без интернета. Xray остаётся native; MTProxy — Docker.
"""
from __future__ import annotations

import logging
import time

import docker
from docker.errors import APIError, NotFound
from docker.models.containers import Container
from docker.types import LogConfig

import config
import host_exec
from docker_utils import ensure_image, format_docker_api_error

logger = logging.getLogger(__name__)


class WireGuardError(RuntimeError):
    """Ошибка WireGuard Docker-сервера."""


WireGuardDockerError = WireGuardError


def _log_config() -> LogConfig:
    return LogConfig(
        type=LogConfig.types.JSON,
        config=config.DOCKER_LOG_CONFIG["config"],
    )


class WireGuardManager:
    def __init__(self) -> None:
        try:
            self._client = docker.from_env()
            self._client.ping()
        except Exception as exc:
            raise WireGuardError(
                "Docker недоступен для WireGuard. Нужен Docker как у wg-easy."
            ) from exc

    def _get_container(self) -> Container | None:
        try:
            return self._client.containers.get(config.WG_CONTAINER_NAME)
        except NotFound:
            return None

    def is_running(self) -> bool:
        return self.get_status() == "running"

    def get_status(self) -> str:
        container = self._get_container()
        if container is None:
            return "missing"
        container.reload()
        return container.status

    def _stop_native_wg_quick(self) -> None:
        """Освобождаем UDP 51820: native wg-quick и Docker не могут слушать вместе."""
        try:
            host_exec.systemctl("disable", "--now", config.WG_SYSTEMD_UNIT, check=False)
            host_exec.run(["wg-quick", "down", config.WG_INTERFACE_NAME], check=False)
            host_exec.run(["ip", "link", "delete", "dev", config.WG_INTERFACE_NAME], check=False)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Не удалось остановить native wg-quick: %s", exc)

    def write_config(self, conf_text: str) -> None:
        wg_confs = config.WG_CONFIG_DIR / "wg_confs"
        wg_confs.mkdir(parents=True, exist_ok=True)
        path = wg_confs / f"{config.WG_INTERFACE_NAME}.conf"
        path.write_text(conf_text, encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def ensure_server_running(
        self,
        *,
        conf_text: str,
        listen_port: int,
        subnet: str,
        xray_port: int | None = None,  # noqa: ARG002 — совместимость вызова
    ) -> None:
        self._stop_native_wg_quick()
        self.write_config(conf_text)

        container = self._get_container()
        if container is not None:
            container.reload()
            if container.status == "running":
                self._ensure_config_writable(container)
                # Конфиг на диске уже новый — применяем peer-ов и NAT.
                code, out = container.exec_run(
                    [
                        "bash", "-c",
                        f"wg syncconf {config.WG_INTERFACE_NAME} "
                        f"<(wg-quick strip /config/wg_confs/{config.WG_INTERFACE_NAME}.conf)",
                    ]
                )
                if code != 0:
                    logger.warning("syncconf: %s — restart", out.decode("utf-8", "replace"))
                    container.restart(timeout=10)
                    self._wait_running(container)
                    self.wait_until_interface_ready()
                self._ensure_nat_inside(subnet)
                return
            logger.warning(
                "Контейнер WG в статусе %s — пересоздаю", container.status,
            )
            try:
                container.remove(force=True)
            except APIError as exc:
                raise WireGuardError(
                    f"Не удалось удалить контейнер WG: {format_docker_api_error(exc)}"
                ) from exc

        logger.info(
            "Создаю WireGuard Docker (wg-easy style) udp/%d", listen_port,
        )
        try:
            ensure_image(self._client, config.WG_DOCKER_IMAGE)
            run_kwargs = dict(
                image=config.WG_DOCKER_IMAGE,
                name=config.WG_CONTAINER_NAME,
                detach=True,
                restart_policy={"Name": "unless-stopped"},
                cap_add=["NET_ADMIN", "SYS_MODULE"],
                sysctls={
                    "net.ipv4.conf.all.src_valid_mark": "1",
                    "net.ipv4.ip_forward": "1",
                },
                ports={f"{listen_port}/udp": listen_port},
                # ВАЖНО: PEERS не задаём — иначе linuxserver затрёт наш wg0.conf
                environment={"PUID": "0", "PGID": "0"},
                volumes={
                    str(config.WG_CONFIG_DIR): {"bind": "/config", "mode": "rw"},
                    "/lib/modules": {"bind": "/lib/modules", "mode": "ro"},
                },
                log_config=_log_config(),
            )
            try:
                container = self._client.containers.run(
                    **run_kwargs,
                    devices=["/dev/net/tun:/dev/net/tun"],
                )
            except APIError as tun_exc:
                logger.warning(
                    "WG без /dev/net/tun (%s), пробую без devices",
                    format_docker_api_error(tun_exc),
                )
                container = self._client.containers.run(**run_kwargs)
        except RuntimeError as exc:
            raise WireGuardError(str(exc)) from exc
        except APIError as exc:
            raise WireGuardError(
                f"Не удалось создать контейнер WG: {format_docker_api_error(exc)}"
            ) from exc

        self._wait_running(container)
        self._ensure_config_writable(container)
        self.wait_until_interface_ready()
        self._ensure_nat_inside(subnet)

    def _ensure_config_writable(self, container: Container) -> None:
        try:
            container.exec_run(["chmod", "-R", "a+rwX", "/config"])
        except APIError:
            pass

    def _wait_running(self, container: Container) -> None:
        deadline = time.monotonic() + config.WG_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            container.reload()
            if container.status == "running":
                return
            if container.status in {"exited", "dead"}:
                logs = container.logs(tail=40).decode("utf-8", "replace")
                raise WireGuardError(
                    f"Контейнер WG упал ({container.status}):\n{logs}"
                )
            time.sleep(0.5)
        raise WireGuardError("Контейнер WG не стал running вовремя")

    def wait_until_interface_ready(self, timeout: float | None = None) -> None:
        if timeout is None:
            timeout = config.WG_INTERFACE_TIMEOUT_SECONDS
        container = self._get_container()
        if container is None:
            raise WireGuardError("Контейнер WG не найден")
        deadline = time.monotonic() + timeout
        last = ""
        forced = False
        while time.monotonic() < deadline:
            container.reload()
            if container.status in {"exited", "dead"}:
                logs = container.logs(tail=40).decode("utf-8", "replace")
                raise WireGuardError(f"Контейнер WG упал:\n{logs}")
            code, out = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME]
            )
            if code == 0:
                return
            last = out.decode("utf-8", "replace")
            elapsed = timeout - (deadline - time.monotonic())
            if not forced and elapsed >= 5.0:
                forced = True
                container.exec_run(
                    [
                        "bash", "-c",
                        f"wg-quick up /config/wg_confs/{config.WG_INTERFACE_NAME}.conf "
                        f"|| true",
                    ]
                )
            time.sleep(1.0)
        raise WireGuardError(
            f"wg0 не поднялся за {timeout:.0f}с: {last}\n"
            f"{container.logs(tail=30).decode('utf-8', 'replace')}"
        )

    def _ensure_nat_inside(self, subnet: str) -> None:
        """Дожимает NAT внутри контейнера (как WG_POST_UP у wg-easy)."""
        container = self._get_container()
        if container is None:
            return
        network_cidr = subnet if "/" in subnet else f"{subnet}/24"
        script = f"""
set -e
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT
iptables -t nat -C POSTROUTING -s {network_cidr} -o eth0 -j MASQUERADE 2>/dev/null \\
  || iptables -t nat -A POSTROUTING -s {network_cidr} -o eth0 -j MASQUERADE
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
echo NAT_OK
iptables -t nat -S POSTROUTING
wg show || true
"""
        code, out = container.exec_run(["bash", "-c", script])
        text = out.decode("utf-8", "replace")
        if code != 0:
            raise WireGuardError(f"NAT внутри контейнера не применился: {text}")
        logger.info("WG container NAT: %s", text.strip().replace("\n", " | "))

    def reload_config(self, *, conf_text: str, listen_port: int, subnet: str) -> None:
        self.write_config(conf_text)
        container = self._get_container()
        if container is None or not self.is_running():
            self.ensure_server_running(
                conf_text=conf_text, listen_port=listen_port, subnet=subnet,
            )
            return
        self._ensure_config_writable(container)
        code, out = container.exec_run(
            [
                "bash", "-c",
                f"wg syncconf {config.WG_INTERFACE_NAME} "
                f"<(wg-quick strip /config/wg_confs/{config.WG_INTERFACE_NAME}.conf)",
            ]
        )
        if code != 0:
            logger.warning("syncconf failed (%s) — restart container", out)
            container.restart(timeout=10)
            self._wait_running(container)
            self.wait_until_interface_ready()
        self._ensure_nat_inside(subnet)

    def get_peer_last_handshakes(self) -> dict[str, int]:
        container = self._get_container()
        if container is None:
            return {}
        try:
            code, out = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME, "latest-handshakes"]
            )
        except APIError:
            return {}
        if code != 0:
            return {}
        result: dict[str, int] = {}
        for line in out.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                continue
        return result

    def get_peer_transfer_stats(self) -> dict[str, tuple[int, int]]:
        container = self._get_container()
        if container is None:
            return {}
        try:
            code, out = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME, "transfer"]
            )
        except APIError:
            return {}
        if code != 0:
            return {}
        result: dict[str, tuple[int, int]] = {}
        for line in out.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            try:
                result[parts[0]] = (int(parts[1]), int(parts[2]))
            except ValueError:
                continue
        return result

    def restart_server(self) -> None:
        container = self._get_container()
        if container is None:
            raise WireGuardError("Контейнер WG не найден")
        try:
            container.restart(timeout=10)
        except APIError as exc:
            raise WireGuardError(f"Не удалось перезапустить WG: {exc}") from exc
        self._wait_running(container)
        self.wait_until_interface_ready()

    def remove_server(self) -> None:
        container = self._get_container()
        if container is None:
            return
        try:
            container.remove(force=True)
        except APIError as exc:
            raise WireGuardError(f"Не удалось удалить контейнер WG: {exc}") from exc
