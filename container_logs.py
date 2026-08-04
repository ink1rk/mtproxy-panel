"""
Источники логов для страницы /logs:
- Docker-контейнеры MTProxy
- journalctl для native WireGuard / Xray
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import docker
from docker.errors import DockerException, NotFound

import config
import host_exec

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ContainerLogSource:
    """Пункт в выпадающем списке источников логов на /logs."""

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
    sources: list[ContainerLogSource] = []

    # Native VPN units
    sources.append(ContainerLogSource(name="journal:wg", label="WireGuard (systemd)"))
    sources.append(ContainerLogSource(name="journal:xray", label="Xray/VLESS (systemd)"))

    client = _get_client()
    if client is None:
        return sources

    try:
        containers = client.containers.list(all=True)
    except DockerException:
        return sources

    for container in containers:
        name = container.name
        if name.startswith(config.CONTAINER_NAME_PREFIX):
            sources.append(ContainerLogSource(name=name, label=f"MTProxy: {name}"))
        # Старые docker WG/Xray — только если ещё остались после миграции
        elif name in {"wg_server", "xray_server"}:
            sources.append(ContainerLogSource(name=name, label=f"(legacy docker) {name}"))

    return sources


def get_container_logs(container_name: str, tail: int) -> list[str]:
    if container_name == "journal:wg":
        return host_exec.journalctl_unit(config.WG_SYSTEMD_UNIT, lines=tail)
    if container_name == "journal:xray":
        return host_exec.journalctl_unit(config.XRAY_SYSTEMD_UNIT, lines=tail)

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
