"""
Слой работы с Docker SDK. Никакой бизнес-логики MTProxy —
только операции над контейнерами: создание, удаление, проверка статуса.
"""
from __future__ import annotations

import logging
import time

import docker
from docker.errors import APIError, NotFound
from docker.models.containers import Container

import config

logger = logging.getLogger(__name__)


class DockerUnavailableError(RuntimeError):
    """Docker daemon недоступен."""


class ContainerStartError(RuntimeError):
    """Контейнер не смог перейти в состояние running."""


class ContainerRemovalTimeoutError(RuntimeError):
    """Контейнер не был удалён за отведённый таймаут."""


class DockerManager:
    """Инкапсулирует все взаимодействия с Docker daemon."""

    def __init__(self) -> None:
        try:
            self._client = docker.from_env()
            self._client.ping()
        except Exception as exc:  # docker.errors.DockerException и производные
            raise DockerUnavailableError(
                "Docker daemon недоступен. Убедитесь, что Docker запущен "
                "и текущий пользователь имеет к нему доступ."
            ) from exc

    def remove_container_if_exists(
        self,
        container_name: str,
        timeout: float = config.DOCKER_CONTAINER_REMOVE_TIMEOUT_SECONDS,
    ) -> None:
        """
        Если контейнер с указанным именем существует — останавливает
        и удаляет его, дожидаясь полного удаления.
        """
        try:
            container = self._client.containers.get(container_name)
        except NotFound:
            return

        logger.info("Найден существующий контейнер '%s', удаляю", container_name)
        try:
            container.remove(force=True)
        except APIError as exc:
            logger.error("Ошибка при удалении контейнера '%s': %s", container_name, exc)
            raise

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self._client.containers.get(container_name)
                time.sleep(config.DOCKER_CONTAINER_POLL_INTERVAL_SECONDS)
            except NotFound:
                return
        raise ContainerRemovalTimeoutError(
            f"Контейнер '{container_name}' не был удалён за {timeout} секунд"
        )

    def create_mtproxy_container(
        self,
        container_name: str,
        host_port: int,
        secret: str,
    ) -> Container:
        """Создаёт и запускает контейнер telegrammessenger/proxy."""
        container = self._client.containers.run(
            config.MTPROXY_DOCKER_IMAGE,
            name=container_name,
            detach=True,
            restart_policy={"Name": "unless-stopped"},
            ports={f"{config.CONTAINER_INTERNAL_PORT}/tcp": host_port},
            environment={"SECRET": secret},
        )
        return container

    def wait_until_running(
        self,
        container: Container,
        timeout: float = config.DOCKER_CONTAINER_START_TIMEOUT_SECONDS,
    ) -> bool:
        """
        Опрашивает статус контейнера через reload() до тех пор,
        пока он не станет 'running', либо не истечёт timeout.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            container.reload()
            if container.status == "running":
                return True
            if container.status in {"exited", "dead"}:
                return False
            time.sleep(config.DOCKER_CONTAINER_POLL_INTERVAL_SECONDS)
        return False

    def get_status(self, container_name: str) -> str:
        """Возвращает текущий статус контейнера, либо 'missing'."""
        try:
            container = self._client.containers.get(container_name)
            container.reload()
            return container.status
        except NotFound:
            return "missing"

    def remove_container(self, container_name: str) -> None:
        """Принудительно останавливает и удаляет контейнер, если он существует."""
        try:
            container = self._client.containers.get(container_name)
            container.remove(force=True)
        except NotFound:
            logger.warning(
                "Контейнер '%s' уже отсутствует при попытке удаления", container_name
            )
