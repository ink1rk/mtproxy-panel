"""
Общие хелперы Docker SDK: безопасный pull образов и человекочитаемые
ошибки. Вынесено отдельно, чтобы MTProxy / WireGuard / Xray не дублировали
одну и ту же логику «контейнер не создался, потому что образ не скачался».
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError

import docker
from docker.errors import APIError, ImageNotFound, NotFound

logger = logging.getLogger(__name__)

# Первый pull linuxserver/wireguard на медленном канале легко занимает минуты.
# Без таймаута форма в браузере «висит вечно».
DEFAULT_IMAGE_PULL_TIMEOUT_SECONDS = 180.0


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


def ensure_image(
    client: docker.DockerClient,
    image: str,
    *,
    timeout_seconds: float = DEFAULT_IMAGE_PULL_TIMEOUT_SECONDS,
) -> None:
    """
    Гарантирует, что образ есть локально. Если нет — делает pull с таймаутом.
    Бросает RuntimeError с понятным текстом (для показа пользователю),
    а не сырой '500 Server Error for .../images/create'.
    """
    try:
        client.images.get(image)
        logger.info("Docker-образ '%s' уже есть локально", image)
        return
    except (ImageNotFound, NotFound):
        pass

    logger.info("Скачиваю Docker-образ '%s' (таймаут %.0fс)…", image, timeout_seconds)

    def _pull() -> None:
        client.images.pull(image)
        client.images.get(image)

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_pull)
            future.result(timeout=timeout_seconds)
    except FuturesTimeoutError as exc:
        raise RuntimeError(
            f"Скачивание Docker-образа '{image}' превысило {timeout_seconds:.0f}с. "
            f"Страница из-за этого «зависает». На сервере выполните заранее: "
            f"docker pull {image}  затем повторите настройку в панели."
        ) from exc
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
