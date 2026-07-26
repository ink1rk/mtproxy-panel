"""
Просмотр логов Docker-контейнеров (MTProxy/WireGuard/Xray) прямо в панели.

Отдельный тонкий слой, не связанный с бизнес-логикой конкретных сервисов —
только чтение списка релевантных контейнеров и их вывода через Docker SDK.
Не поднимает исключений наружу без необходимости: если Docker недоступен,
возвращает пустой список/сообщение об ошибке, чтобы страница логов всё равно
открывалась.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import docker
from docker.errors import DockerException, NotFound

import config

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ContainerLogSource:
    """Один пункт в выпадающем списке источников логов на странице /logs."""

    name: str
    label: str


def _get_client() -> docker.DockerClient | None:
    try:
        client = docker.from_env()
        client.ping()
        return client
    except DockerException:
        return None


def list_log_sources() -> list[ContainerLogSource]:
    """
    Возвращает список контейнеров, логи которых можно посмотреть: все текущие
    MTProxy-контейнеры (по префиксу имени) + WireGuard/Xray серверы, если они
    существуют (независимо от того, запущены они сейчас или остановлены).
    """
    client = _get_client()
    if client is None:
        return []

    sources: list[ContainerLogSource] = []
    try:
        containers = client.containers.list(all=True)
    except DockerException:
        return []

    for container in containers:
        name = container.name
        if name.startswith(config.CONTAINER_NAME_PREFIX):
            sources.append(ContainerLogSource(name=name, label=f"MTProxy: {name}"))
        elif name == config.WG_CONTAINER_NAME:
            sources.append(ContainerLogSource(name=name, label="WireGuard-сервер"))
        elif name == config.XRAY_CONTAINER_NAME:
            sources.append(ContainerLogSource(name=name, label="VLESS/Xray-сервер"))

    return sources


def get_container_logs(container_name: str, tail: int) -> list[str]:
    """
    Возвращает последние `tail` строк логов указанного контейнера.
    `container_name` обязательно должен быть одним из имён, возвращаемых
    list_log_sources() — вызывающий код (роут) отвечает за эту проверку,
    чтобы не открывать произвольный доступ к логам любого контейнера на хосте.
    """
    client = _get_client()
    if client is None:
        return ["[Docker недоступен — не удалось получить логи контейнера]"]

    try:
        container = client.containers.get(container_name)
    except NotFound:
        return [f"[контейнер '{container_name}' не найден]"]
    except DockerException as exc:
        return [f"[ошибка Docker: {exc}]"]

    try:
        raw = container.logs(tail=tail, timestamps=True)
    except DockerException as exc:
        return [f"[не удалось прочитать логи контейнера: {exc}]"]

    text = raw.decode("utf-8", errors="replace")
    return text.splitlines()
