"""
Docker-слой для WireGuard VPN сервера.

В отличие от MTProxy (где каждый прокси — отдельный контейнер), WireGuard
работает как ОДИН постоянный контейнер-сервер, обслуживающий множество
peer-ов через один и тот же UDP-порт. Peer-ы добавляются/удаляются
"горячо" через `wg syncconf` — без перезапуска контейнера и без разрыва
соединений остальных клиентов.

Образ: lscr.io/linuxserver/wireguard с переменной окружения PEERS=0 —
это переводит образ в режим "bare", где он НЕ генерирует peer-конфиги
самостоятельно, а просто поднимает интерфейс из wg_confs/wg0.conf,
который полностью формирует и обновляет наша панель.
"""
from __future__ import annotations

import logging
import time

import docker
from docker.errors import APIError, NotFound
from docker.models.containers import Container

import config

logger = logging.getLogger(__name__)


class WireGuardDockerError(RuntimeError):
    """Ошибка при работе с Docker-контейнером WireGuard-сервера."""


class WireGuardManager:
    """Управляет жизненным циклом единственного контейнера WireGuard-сервера."""

    def __init__(self) -> None:
        try:
            self._client = docker.from_env()
            self._client.ping()
        except Exception as exc:
            raise WireGuardDockerError(
                "Docker daemon недоступен для управления WireGuard-сервером"
            ) from exc

    def _get_container(self) -> Container | None:
        try:
            return self._client.containers.get(config.WG_CONTAINER_NAME)
        except NotFound:
            return None

    def is_running(self) -> bool:
        container = self._get_container()
        if container is None:
            return False
        container.reload()
        return container.status == "running"

    def get_status(self) -> str:
        container = self._get_container()
        if container is None:
            return "missing"
        container.reload()
        return container.status

    def ensure_server_running(self, listen_port: int) -> None:
        """
        Создаёт (если не существует) и запускает контейнер WireGuard-сервера.
        Идемпотентно: если контейнер уже существует и работает — ничего не делает.
        Конфигурация (wg0.conf) читается контейнером из смонтированной директории
        config.WG_CONFIG_DIR/wg_confs/wg0.conf, которую формирует панель.
        """
        container = self._get_container()
        if container is not None:
            container.reload()
            if container.status == "running":
                return
            logger.info("Контейнер WireGuard существует, но не запущен — запускаю")
            try:
                container.start()
            except APIError as exc:
                raise WireGuardDockerError(f"Не удалось запустить контейнер WireGuard: {exc}") from exc
            self._wait_running(container)
            return

        logger.info("Создаю контейнер WireGuard-сервера на порту %d/udp", listen_port)
        try:
            container = self._client.containers.run(
                config.WG_DOCKER_IMAGE,
                name=config.WG_CONTAINER_NAME,
                detach=True,
                restart_policy={"Name": "unless-stopped"},
                cap_add=["NET_ADMIN", "SYS_MODULE"],
                sysctls={
                    "net.ipv4.conf.all.src_valid_mark": "1",
                    "net.ipv4.ip_forward": "1",
                },
                ports={f"{listen_port}/udp": listen_port},
                environment={"PEERS": "0", "PUID": "0", "PGID": "0"},
                volumes={str(config.WG_CONFIG_DIR): {"bind": "/config", "mode": "rw"}},
            )
        except APIError as exc:
            raise WireGuardDockerError(f"Не удалось создать контейнер WireGuard: {exc}") from exc

        self._wait_running(container)

    def _wait_running(self, container: Container) -> None:
        deadline = time.monotonic() + config.DOCKER_WG_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            container.reload()
            if container.status == "running":
                return
            if container.status in {"exited", "dead"}:
                raise WireGuardDockerError(
                    f"Контейнер WireGuard завершился со статусом '{container.status}' при запуске"
                )
            time.sleep(0.5)
        raise WireGuardDockerError("Контейнер WireGuard не перешёл в статус 'running' за отведённое время")

    def reload_config(self) -> None:
        """
        Применяет обновлённый wg0.conf "на горячую" через `wg syncconf`,
        не разрывая существующие соединения других peer-ов.
        """
        container = self._get_container()
        if container is None:
            raise WireGuardDockerError("Контейнер WireGuard не найден — сервер ещё не настроен")

        exit_code, output = container.exec_run(
            [
                "bash", "-c",
                f"wg syncconf {config.WG_INTERFACE_NAME} "
                f"<(wg-quick strip /config/wg_confs/{config.WG_INTERFACE_NAME}.conf)",
            ],
        )
        if exit_code != 0:
            raise WireGuardDockerError(
                f"wg syncconf завершился с ошибкой (код {exit_code}): {output.decode('utf-8', 'replace')}"
            )
        logger.info("Конфигурация WireGuard применена на горячую (wg syncconf)")

    def remove_server(self) -> None:
        """Полностью удаляет контейнер WireGuard-сервера (для полного сброса VPN)."""
        container = self._get_container()
        if container is None:
            return
        try:
            container.remove(force=True)
        except APIError as exc:
            raise WireGuardDockerError(f"Не удалось удалить контейнер WireGuard: {exc}") from exc
