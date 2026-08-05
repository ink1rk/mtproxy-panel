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
import docker_iptables

logger = logging.getLogger(__name__)

_DOCKER_CHAIN_ERROR_MARKERS = (
    "no chain/target/match by that name",
    "unable to enable dnat rule",
)


def _looks_like_docker_chain_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(marker in text for marker in _DOCKER_CHAIN_ERROR_MARKERS)


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
        *,
        use_host_network: bool = False,
    ) -> Container:
        """
        Создаёт и запускает контейнер telegrammessenger/proxy.

        На Ubuntu 24.04+/26.04 Docker периодически теряет цепочку
        nat/DOCKER (iptables → nft-backend после ребута/апдейта) — публикация
        портов падает с "No chain/target/match by that name". Чиним один раз
        (iptables-legacy + restart docker) и повторяем создание контейнера.

        use_host_network: обходит Docker bridge/DNAT целиком (как у native
        WireGuard/Xray). На части VPS (подтверждено живым тестом: локально
        и через container-IP хендшейк проходит, через внешний DNAT — TCP
        SYN/ACK проходят, но сразу после первых байт данных приходит RST
        ровно через 5с) bridge-режим Docker ломает реальный TCP-обмен для
        MTProxy, оставаясь рабочим для простого TCP-коннекта. Host-режим
        обходит эту проблему полностью — подтверждено 3/3 успешных
        MTProto-хендшейков. Образ жёстко слушает порт 443 (нет env для
        смены), поэтому host-режим применим только для host_port=443 и
        только для ОДНОГО инстанса одновременно.
        """
        from docker.types import LogConfig

        log_config = LogConfig(
            type=LogConfig.types.JSON,
            config=config.DOCKER_LOG_CONFIG["config"],
        )

        def _run() -> Container:
            if use_host_network:
                return self._client.containers.run(
                    config.MTPROXY_DOCKER_IMAGE,
                    name=container_name,
                    detach=True,
                    restart_policy={"Name": "unless-stopped"},
                    network_mode="host",
                    environment={"SECRET": secret},
                    log_config=log_config,
                )
            return self._client.containers.run(
                config.MTPROXY_DOCKER_IMAGE,
                name=container_name,
                detach=True,
                restart_policy={"Name": "unless-stopped"},
                ports={f"{config.CONTAINER_INTERNAL_PORT}/tcp": host_port},
                environment={"SECRET": secret},
                log_config=log_config,
            )

        try:
            return _run()
        except APIError as exc:
            if not _looks_like_docker_chain_error(exc):
                raise
            logger.warning(
                "Docker nat/DOCKER chain отсутствует, чиню (iptables-legacy + restart): %s",
                exc,
            )
            try:
                self._client.containers.get(container_name).remove(force=True)
            except NotFound:
                pass
            try:
                docker_iptables.ensure_docker_iptables(force_repair=True)
            except docker_iptables.DockerIptablesError as repair_exc:
                raise APIError(
                    f"Docker DOCKER chain чинить не удалось: {repair_exc}"
                ) from exc
            self._client = docker.from_env()
            return _run()

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
