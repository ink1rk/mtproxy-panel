"""
Docker-слой для WireGuard VPN сервера.

В отличие от MTProxy (где каждый прокси — отдельный контейнер), WireGuard
работает как ОДИН постоянный контейнер-сервер, обслуживающий множество
peer-ов через один и тот же UDP-порт. Peer-ы добавляются/удаляются
"горячо" через `wg syncconf` — без перезапуска контейнера и без разрыва
соединений остальных клиентов.

Образ: lscr.io/linuxserver/wireguard БЕЗ переменной окружения PEERS —
это официально документированный "bare/client mode": образ НЕ генерирует
peer-конфиги самостоятельно, а просто поднимает интерфейс из готового
wg_confs/wg0.conf, который полностью формирует и обновляет наша панель.
(Важно: даже PEERS=0 — это НЕ то же самое, что отсутствие переменной —
см. подробный комментарий в ensure_server_running() ниже.)
"""
from __future__ import annotations

import logging
import time

import docker
from docker.errors import APIError, NotFound
from docker.models.containers import Container
from docker.types import LogConfig

import config

logger = logging.getLogger(__name__)


class WireGuardDockerError(RuntimeError):
    """Ошибка при работе с Docker-контейнером WireGuard-сервера."""


def _docker_log_config() -> LogConfig:
    return LogConfig(
        type=LogConfig.types.JSON,
        config=config.DOCKER_LOG_CONFIG["config"],
    )


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
                # ВАЖНО: PEERS не задаём вовсе (а не "0"!). У linuxserver/wireguard
                # ЛЮБОЕ непустое значение PEERS (включая "0") включает "серверный"
                # режим — образ САМ генерирует новый wg0.conf (со своим случайным
                # приватным ключом и служебной подсетью 10.13.13.0/24!), полностью
                # затирая наш файл ДО первого 'wg-quick up'. Из-за этого реальный
                # запущенный интерфейс не совпадал ни по ключу, ни по подсети с тем,
                # что панель хранит в БД и отдаёт клиентам — туннель не мог поднять
                # соединение и/или не мог маршрутизировать трафик пиров (не было
                # маршрута до подсети пиров в таблице маршрутизации контейнера).
                # Официально документированный "bare/client mode" — не задавать
                # PEERS вообще и просто положить готовый конфиг в wg_confs/*.conf.
                environment={"PUID": "0", "PGID": "0"},
                volumes={str(config.WG_CONFIG_DIR): {"bind": "/config", "mode": "rw"}},
                log_config=_docker_log_config(),
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

    def get_peer_last_handshakes(self) -> dict[str, int]:
        """
        Возвращает {public_key: unix_timestamp последнего handshake}. WireGuard
        не пишет лог о каждом подключении (это не TCP-прокси, а UDP-туннель без
        событийного протокола) — время последнего handshake — самый прямой
        показатель "жив ли клиент" ("0" из вывода wg означает "ни разу").
        """
        container = self._get_container()
        if container is None:
            return {}
        try:
            exit_code, output = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME, "latest-handshakes"]
            )
        except APIError:
            return {}
        if exit_code != 0:
            return {}

        result: dict[str, int] = {}
        for line in output.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            public_key, timestamp = parts
            try:
                result[public_key] = int(timestamp)
            except ValueError:
                continue
        return result

    def get_peer_transfer_stats(self) -> dict[str, tuple[int, int]]:
        """
        Возвращает {public_key: (rx_bytes, tx_bytes)} по выводу
        `wg show <iface> transfer`. Это единственный встроенный счётчик
        трафика WireGuard — в веб-логах UDP-туннеля отдельных сессий нет.
        """
        container = self._get_container()
        if container is None:
            return {}
        try:
            exit_code, output = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME, "transfer"]
            )
        except APIError:
            return {}
        if exit_code != 0:
            return {}

        result: dict[str, tuple[int, int]] = {}
        for line in output.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            public_key, rx_raw, tx_raw = parts
            try:
                result[public_key] = (int(rx_raw), int(tx_raw))
            except ValueError:
                continue
        return result

    def wait_until_interface_ready(self, timeout: float = 15.0) -> None:
        """
        Ждёт, пока внутри контейнера поднимется интерфейс wg0.
        Нужен после первого старта: linuxserver-entrypoint поднимает
        wg-quick асинхронно, и слишком ранний `wg syncconf` падает.
        """
        container = self._get_container()
        if container is None:
            raise WireGuardDockerError("Контейнер WireGuard не найден — сервер ещё не настроен")

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            exit_code, _output = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME]
            )
            if exit_code == 0:
                return
            time.sleep(0.5)
        raise WireGuardDockerError(
            f"Интерфейс {config.WG_INTERFACE_NAME} не поднялся внутри контейнера за {timeout:.0f}с"
        )

    def restart_server(self) -> None:
        """Перезапускает контейнер WireGuard-сервера, не трогая конфигурацию/peer-ов."""
        container = self._get_container()
        if container is None:
            raise WireGuardDockerError("Контейнер WireGuard не найден — сервер ещё не настроен")
        try:
            container.restart(timeout=10)
        except APIError as exc:
            raise WireGuardDockerError(f"Не удалось перезапустить контейнер WireGuard: {exc}") from exc
        self._wait_running(container)

    def remove_server(self) -> None:
        """Полностью удаляет контейнер WireGuard-сервера (для полного сброса VPN)."""
        container = self._get_container()
        if container is None:
            return
        try:
            container.remove(force=True)
        except APIError as exc:
            raise WireGuardDockerError(f"Не удалось удалить контейнер WireGuard: {exc}") from exc
