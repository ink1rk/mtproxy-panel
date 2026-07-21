"""
Сервисный слой: единственная точка входа для бизнес-операций над прокси.
Routes не должны напрямую обращаться к Docker или SQLite — только сюда.
"""
from __future__ import annotations

import logging

import utils
from docker_manager import DockerManager, DockerUnavailableError
from mtproxy import MTProxyCreationError, MTProxyProvisioner
from models import Proxy
from repository import ProxyNotFoundError, ProxyRepository

logger = logging.getLogger(__name__)

__all__ = [
    "ProxyService",
    "ProxyServiceError",
]


class ProxyServiceError(RuntimeError):
    """Единая ошибка сервисного слоя, безопасная для показа пользователю."""


class ProxyService:
    """Оркестрирует создание, чтение, удаление прокси на уровне бизнес-логики."""

    def __init__(self) -> None:
        self._repository = ProxyRepository()
        try:
            self._docker_manager = DockerManager()
        except DockerUnavailableError as exc:
            logger.critical("Docker недоступен при инициализации сервиса: %s", exc)
            raise ProxyServiceError(str(exc)) from exc
        self._provisioner = MTProxyProvisioner(self._docker_manager)

    def list_proxies(self) -> list[Proxy]:
        """Возвращает список всех прокси с актуальным статусом контейнера."""
        proxies = self._repository.get_all()
        refreshed: list[Proxy] = []
        for proxy in proxies:
            live_status = self._docker_manager.get_status(proxy.container_name)
            if live_status != proxy.status:
                self._repository.update_status(proxy.id, live_status)
                proxy = self._repository.get_by_id(proxy.id)
            refreshed.append(proxy)
        return refreshed

    def create_proxy(self) -> Proxy:
        """
        Полный цикл создания прокси: провижининг контейнера,
        генерация QR, сохранение в БД. При любой ошибке — чистый откат.
        """
        try:
            provisioned = self._provisioner.provision()
        except MTProxyCreationError as exc:
            raise ProxyServiceError(str(exc)) from exc

        qr_filename = f"{provisioned.container_name}.png"
        try:
            utils.generate_qr_code(provisioned.tg_link, qr_filename)
        except Exception as exc:
            logger.error("Ошибка генерации QR для '%s': %s", provisioned.container_name, exc)
            self._provisioner.deprovision(provisioned.container_name)
            raise ProxyServiceError(f"Не удалось сгенерировать QR-код: {exc}") from exc

        try:
            proxy = self._repository.create(
                container_name=provisioned.container_name,
                ip=provisioned.ip,
                port=provisioned.port,
                secret=provisioned.secret,
                tg_link=provisioned.tg_link,
                https_link=provisioned.https_link,
                qr_filename=qr_filename,
                status="running",
            )
        except Exception as exc:
            logger.error(
                "Ошибка сохранения прокси '%s' в БД: %s", provisioned.container_name, exc
            )
            utils.delete_qr_code(qr_filename)
            self._provisioner.deprovision(provisioned.container_name)
            raise ProxyServiceError(f"Не удалось сохранить прокси в базе данных: {exc}") from exc

        return proxy

    def delete_proxy(self, proxy_id: int) -> None:
        """Удаляет прокси: контейнер, QR-файл и запись в БД."""
        try:
            proxy = self._repository.get_by_id(proxy_id)
        except ProxyNotFoundError as exc:
            raise ProxyServiceError(str(exc)) from exc

        try:
            self._provisioner.deprovision(proxy.container_name)
        except Exception as exc:
            logger.error(
                "Ошибка удаления контейнера '%s': %s", proxy.container_name, exc
            )
            raise ProxyServiceError(f"Не удалось удалить контейнер: {exc}") from exc

        utils.delete_qr_code(proxy.qr_filename)
        self._repository.delete(proxy_id)
        logger.info("Прокси id=%d ('%s') удалён", proxy_id, proxy.container_name)
