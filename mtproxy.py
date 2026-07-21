"""
Оркестрация жизненного цикла MTProxy-контейнера.

Алгоритм создания (строго по шагам, с откатом на любой ошибке):
  1. Определить порт: либо проверить и занять запрошенный пользователем,
     либо найти свободный TCP-порт автоматически.
  2. Сгенерировать криптостойкий базовый secret и, если нужно, построить
     его варианты для контейнера (dd/ee) и для клиентских ссылок.
  3. Создать Docker-контейнер.
  4. Дождаться запуска.
  5. Проверить container.status == "running".
  6. Проверить открытие TCP-порта.
  7. Проверить, что контейнер отвечает (то же TCP-подключение).
  8. Только после успеха всех шагов — данные готовы к сохранению в SQLite.

Любая ошибка на любом шаге -> контейнер останавливается, удаляется,
временные данные (в частности QR, если он уже был создан) очищаются,
наверх поднимается описательное исключение.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import config
import utils
from docker_manager import ContainerRemovalTimeoutError, DockerManager

logger = logging.getLogger(__name__)


class MTProxyCreationError(RuntimeError):
    """Создание MTProxy завершилось ошибкой; состояние полностью откачено."""


@dataclass(frozen=True, slots=True)
class ProvisionedProxy:
    """Результат успешного провижининга контейнера (ещё не сохранён в БД)."""

    container_name: str
    ip: str
    port: int
    link_secret: str
    container_secret: str
    secret_mode: str
    tls_domain: str | None
    tg_link: str
    https_link: str


class MTProxyProvisioner:
    """Создаёт и удаляет MTProxy-контейнеры, гарантируя отсутствие полуготовых состояний."""

    def __init__(self, docker_manager: DockerManager) -> None:
        self._docker = docker_manager

    def provision(
        self,
        *,
        desired_port: int | None = None,
        secret_mode: str = config.SECRET_MODE_CLASSIC,
        tls_domain: str | None = None,
    ) -> ProvisionedProxy:
        if secret_mode not in config.VALID_SECRET_MODES:
            raise MTProxyCreationError(f"Неизвестный режим секрета: '{secret_mode}'")

        container_name = utils.generate_container_name()
        logger.info("Начинаю провижининг прокси '%s'", container_name)

        # Шаг 0: гарантируем отсутствие контейнера с таким именем.
        try:
            self._docker.remove_container_if_exists(container_name)
        except ContainerRemovalTimeoutError as exc:
            raise MTProxyCreationError(str(exc)) from exc

        # Шаг 1: порт — либо запрошенный пользователем (с проверкой), либо случайный.
        try:
            if desired_port is not None:
                port = utils.validate_manual_port(desired_port)
            else:
                port = utils.find_free_port()
        except (utils.NoFreePortError, utils.PortUnavailableError) as exc:
            raise MTProxyCreationError(str(exc)) from exc

        # Шаг 2: секрет и его варианты для контейнера/ссылок.
        base_secret = utils.generate_secret()
        try:
            container_secret = utils.build_container_secret(base_secret, secret_mode, tls_domain)
            link_secret = utils.build_link_secret(base_secret, secret_mode, tls_domain)
        except utils.InvalidTlsDomainError as exc:
            raise MTProxyCreationError(str(exc)) from exc

        # Шаг 3: создание контейнера.
        try:
            container = self._docker.create_mtproxy_container(
                container_name=container_name,
                host_port=port,
                secret=container_secret,
            )
        except Exception as exc:
            logger.error("Не удалось создать контейнер '%s': %s", container_name, exc)
            self._safe_cleanup(container_name)
            raise MTProxyCreationError(
                f"Не удалось создать Docker-контейнер: {exc}"
            ) from exc

        # Шаг 4-5: ожидание запуска и проверка статуса.
        is_running = self._docker.wait_until_running(container)
        if not is_running:
            logger.error("Контейнер '%s' не перешёл в статус running", container_name)
            self._safe_cleanup(container_name)
            raise MTProxyCreationError(
                "Контейнер не запустился (статус не 'running') за отведённое время. "
                "Если использовался режим 'ee', проверьте корректность домена."
            )

        # Шаг 6: определяем публичный IP и проверяем открытие порта.
        try:
            ip = utils.get_server_public_ip()
        except utils.PublicIPLookupError as exc:
            self._safe_cleanup(container_name)
            raise MTProxyCreationError(str(exc)) from exc

        port_open = utils.check_tcp_port_open("127.0.0.1", port)
        if not port_open:
            logger.error("Порт %d контейнера '%s' не открылся", port, container_name)
            self._safe_cleanup(container_name)
            raise MTProxyCreationError(
                f"Порт {port} не открылся в отведённое время — контейнер откачен"
            )

        # Шаг 7: контейнер отвечает (повторная проверка TCP-хендшейка).
        responds = utils.check_tcp_port_open(
            "127.0.0.1", port, timeout=config.TCP_CONNECT_TIMEOUT_SECONDS * 3
        )
        if not responds:
            logger.error("Контейнер '%s' не отвечает на порт %d", container_name, port)
            self._safe_cleanup(container_name)
            raise MTProxyCreationError(
                "Контейнер не отвечает на подключения — состояние откачено"
            )

        tg_link = utils.build_tg_link(ip, port, link_secret)
        https_link = utils.build_https_link(ip, port, link_secret)

        logger.info(
            "Прокси '%s' успешно провижинирован на порту %d (режим секрета: %s)",
            container_name, port, secret_mode,
        )
        return ProvisionedProxy(
            container_name=container_name,
            ip=ip,
            port=port,
            link_secret=link_secret,
            container_secret=container_secret,
            secret_mode=secret_mode,
            tls_domain=tls_domain if secret_mode == config.SECRET_MODE_EE else None,
            tg_link=tg_link,
            https_link=https_link,
        )

    def _safe_cleanup(self, container_name: str) -> None:
        """Гарантированная очистка контейнера при любой ошибке провижининга."""
        try:
            self._docker.remove_container(container_name)
        except Exception as exc:  # noqa: BLE001 - очистка не должна маскировать исходную ошибку
            logger.error(
                "Ошибка при откате контейнера '%s': %s", container_name, exc
            )

    def deprovision(self, container_name: str) -> None:
        """Полностью удаляет контейнер (используется при удалении прокси)."""
        self._docker.remove_container(container_name)
