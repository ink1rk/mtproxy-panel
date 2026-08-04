"""
Docker-слой для Xray (VLESS+REALITY) VPN сервера.

Как и WireGuard, Xray работает как ОДИН постоянный контейнер-сервер,
обслуживающий множество клиентов через один и тот же TCP-порт. В отличие
от WireGuard, у Xray нет простого аналога 'wg syncconf' для горячего
обновления списка клиентов через Docker SDK без дополнительной настройки
gRPC API — поэтому обновление списка клиентов применяется через
перезапись config.json и контролируемый перезапуск контейнера
(быстрая операция, не создающая "полуготовых" состояний благодаря
проверке статуса после каждого перезапуска).
"""
from __future__ import annotations

import json
import logging
import time

import docker
from docker.errors import APIError, NotFound
from docker.models.containers import Container
from docker.types import LogConfig

import config
from docker_utils import ensure_image, format_docker_api_error

logger = logging.getLogger(__name__)


class XrayDockerError(RuntimeError):
    """Ошибка при работе с Docker-контейнером Xray-сервера."""


def _docker_log_config() -> LogConfig:
    return LogConfig(
        type=LogConfig.types.JSON,
        config=config.DOCKER_LOG_CONFIG["config"],
    )


class XrayManager:
    """Управляет жизненным циклом единственного контейнера Xray-сервера."""

    def __init__(self) -> None:
        try:
            self._client = docker.from_env()
            self._client.ping()
        except Exception as exc:
            raise XrayDockerError("Docker daemon недоступен для управления Xray-сервером") from exc

    def _get_container(self) -> Container | None:
        try:
            return self._client.containers.get(config.XRAY_CONTAINER_NAME)
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

    def _write_config_file(self, config_json: dict) -> None:
        config_path = config.XRAY_CONFIG_DIR / "config.json"
        config_path.write_text(json.dumps(config_json, indent=2, ensure_ascii=False), encoding="utf-8")

    def ensure_server_running(self, listen_port: int, config_json: dict) -> None:
        """
        Пишет config.json и создаёт (если не существует) / запускает контейнер
        Xray-сервера. Идемпотентно: если контейнер уже работает — просто
        обновляет файл конфигурации (без применения — для применения у новых
        клиентов используйте apply_config()).
        """
        self._write_config_file(config_json)

        container = self._get_container()
        if container is not None:
            container.reload()
            if container.status == "running":
                return
            logger.info("Контейнер Xray существует, но не запущен — запускаю")
            try:
                container.start()
            except APIError as exc:
                raise XrayDockerError(f"Не удалось запустить контейнер Xray: {exc}") from exc
            self._wait_running(container)
            return

        logger.info("Создаю контейнер Xray-сервера на порту %d/tcp", listen_port)
        try:
            ensure_image(self._client, config.XRAY_DOCKER_IMAGE)
            container = self._client.containers.run(
                config.XRAY_DOCKER_IMAGE,
                name=config.XRAY_CONTAINER_NAME,
                detach=True,
                restart_policy={"Name": "unless-stopped"},
                ports={f"{listen_port}/tcp": listen_port},
                volumes={
                    str(config.XRAY_CONFIG_DIR / "config.json"): {
                        "bind": "/etc/xray/config.json", "mode": "ro",
                    }
                },
                log_config=_docker_log_config(),
            )
        except RuntimeError as exc:
            raise XrayDockerError(str(exc)) from exc
        except APIError as exc:
            raise XrayDockerError(
                f"Не удалось создать контейнер Xray: {format_docker_api_error(exc)}"
            ) from exc

        self._wait_running(container)

    def apply_config(self, config_json: dict) -> None:
        """
        Перезаписывает config.json и перезапускает контейнер, чтобы применить
        изменения (добавление/удаление клиента). Проверяет, что контейнер
        успешно поднялся после перезапуска — иначе поднимает исключение,
        не оставляя сервер в нерабочем состоянии незамеченным.
        """
        self._write_config_file(config_json)

        container = self._get_container()
        if container is None:
            raise XrayDockerError("Контейнер Xray не найден — сервер ещё не настроен")

        try:
            container.restart(timeout=10)
        except APIError as exc:
            raise XrayDockerError(f"Не удалось перезапустить контейнер Xray: {exc}") from exc

        self._wait_running(container)
        logger.info("Конфигурация Xray применена (перезапуск контейнера)")

    def _wait_running(self, container: Container) -> None:
        deadline = time.monotonic() + config.DOCKER_XRAY_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            container.reload()
            if container.status == "running":
                return
            if container.status in {"exited", "dead"}:
                raise XrayDockerError(
                    f"Контейнер Xray завершился со статусом '{container.status}' — проверьте config.json"
                )
            time.sleep(0.5)
        raise XrayDockerError("Контейнер Xray не перешёл в статус 'running' за отведённое время")

    def restart_server(self) -> None:
        """Перезапускает контейнер Xray-сервера, не трогая конфигурацию/клиентов."""
        container = self._get_container()
        if container is None:
            raise XrayDockerError("Контейнер Xray не найден — сервер ещё не настроен")
        try:
            container.restart(timeout=10)
        except APIError as exc:
            raise XrayDockerError(f"Не удалось перезапустить контейнер Xray: {exc}") from exc
        self._wait_running(container)

    def remove_server(self) -> None:
        """Полностью удаляет контейнер Xray-сервера (для полного сброса VPN)."""
        container = self._get_container()
        if container is None:
            return
        try:
            container.remove(force=True)
        except APIError as exc:
            raise XrayDockerError(f"Не удалось удалить контейнер Xray: {exc}") from exc
