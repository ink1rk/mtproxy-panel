"""
Общие хелперы Docker SDK: безопасный pull образов и человекочитаемые
ошибки. Вынесено отдельно, чтобы MTProxy / WireGuard / Xray не дублировали
одну и ту же логику «контейнер не создался, потому что образ не скачался».
"""
from __future__ import annotations

import logging

import docker
from docker.errors import APIError, ImageNotFound, NotFound

logger = logging.getLogger(__name__)


def format_docker_api_error(exc: BaseException) -> str:
    """Достаёт из Docker APIError самое полезное объяснение для UI/логов."""
    parts: list[str] = []
    explanation = getattr(exc, "explanation", None)
    if explanation:
        parts.append(str(explanation).strip())
    message = str(exc).strip()
    if message and message not in parts:
        parts.append(message)
    return " | ".join(parts) if parts else repr(exc)


def ensure_image(client: docker.DockerClient, image: str) -> None:
    """
    Гарантирует, что образ есть локально. Если нет — делает pull.
    Бросает RuntimeError с понятным текстом (для показа пользователю),
    а не сырой '500 Server Error for .../images/create'.
    """
    try:
        client.images.get(image)
        logger.info("Docker-образ '%s' уже есть локально", image)
        return
    except (ImageNotFound, NotFound):
        pass

    logger.info("Скачиваю Docker-образ '%s'…", image)
    try:
        # stream+decode даёт прогресс в логах daemon'а; нам важен финальный
        # результат и нормальный текст ошибки при обрыве registry.
        client.images.pull(image)
        client.images.get(image)  # подтверждаем, что pull реально положил тег
    except APIError as exc:
        detail = format_docker_api_error(exc)
        raise RuntimeError(
            f"Не удалось скачать Docker-образ '{image}'. "
            f"Docker daemon вернул ошибку: {detail}. "
            f"Проверьте на сервере: docker pull {image} "
            f"и доступ к registry (сеть/DNS/firewall/Docker Hub rate limit). "
            f"Если Hub недоступен — настройте registry-mirror в "
            f"/etc/docker/daemon.json и выполните systemctl restart docker."
        ) from exc
    except Exception as exc:  # noqa: BLE001 — любая ошибка pull должна стать понятной
        raise RuntimeError(
            f"Не удалось скачать Docker-образ '{image}': {exc}. "
            f"Проверьте вручную: docker pull {image}"
        ) from exc

    logger.info("Docker-образ '%s' успешно скачан", image)
