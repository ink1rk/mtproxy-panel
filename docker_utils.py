"""Общие хелперы Docker SDK (MTProxy + WireGuard)."""
from __future__ import annotations

import logging

import docker
from docker.errors import APIError, ImageNotFound

logger = logging.getLogger(__name__)


def format_docker_api_error(exc: BaseException) -> str:
    text = str(exc).strip()
    return text or exc.__class__.__name__


def ensure_image(client: docker.DockerClient, image: str, *, timeout: float = 300.0) -> None:
    try:
        client.images.get(image)
        return
    except ImageNotFound:
        pass
    logger.info("Скачиваю Docker-образ %s ...", image)
    try:
        client.images.pull(image)
    except APIError as exc:
        raise RuntimeError(
            f"Не удалось скачать образ {image}: {format_docker_api_error(exc)}. "
            f"Проверьте: docker pull {image}"
        ) from exc
