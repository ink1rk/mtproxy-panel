"""
Точка входа приложения: настройка логирования, инициализация БД,
создание первого администратора, монтирование статики и подключение роутов.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

import auth
import config
from database import init_db
from log_routes import router as log_router
from routes import router
from vpn_routes import router as vpn_router


class TruncatingFileHandler(RotatingFileHandler):
    """
    Как RotatingFileHandler, но вместо переименования в app.log.1/.2/... при
    достижении maxBytes просто обрезает файл до нуля и продолжает писать в
    него же. Никаких архивных файлов на диске не остаётся — по требованию,
    чтобы логи не копились, а перезаписывались.
    """

    def doRollover(self) -> None:
        if self.stream:
            self.stream.close()
            self.stream = None
        # Полностью обрезаем файл (открытие в режиме 'w' у обычного файла
        # логов безопасно: это единственный писатель в него).
        open(self.baseFilename, "w", encoding=self.encoding or "utf-8").close()
        if not self.delay:
            self.stream = self._open()


def configure_logging() -> None:
    """Настраивает логирование в файл (с обрезкой при превышении размера) и в консоль."""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    formatter = logging.Formatter(config.LOG_FORMAT)

    file_handler = TruncatingFileHandler(
        filename=config.LOG_FILE_PATH,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=1,  # значение не используется TruncatingFileHandler.doRollover, но должно быть > 0
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


configure_logging()
logger = logging.getLogger(__name__)


def _ensure_vpn_servers_running() -> None:
    """
    Если WireGuard и/или Xray уже настроены — поднимает native systemd-сервисы
    (wg-quick@wg0 / xray) при старте панели. Ошибки только логируются.
    """
    try:
        from vpn_service import VpnServiceError, WireGuardService

        WireGuardService().ensure_running_if_configured()
    except VpnServiceError as exc:
        logger.warning("WireGuard-сервер не удалось поднять при старте: %s", exc)
    except Exception:  # noqa: BLE001 — сбой VPN-автозапуска не должен ронять панель
        logger.exception("Неожиданная ошибка при автозапуске WireGuard")

    try:
        from vpn_service import VpnServiceError, XrayService

        XrayService().ensure_running_if_configured()
    except VpnServiceError as exc:
        logger.warning("Xray-сервер не удалось поднять при старте: %s", exc)
    except Exception:  # noqa: BLE001
        logger.exception("Неожиданная ошибка при автозапуске Xray")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Запуск приложения '%s'", config.APP_TITLE)
    init_db()

    generated_password = auth.ensure_initial_admin_exists()
    if generated_password is not None:
        banner = (
            "\n"
            "==================================================================\n"
            " СОЗДАНА ПЕРВАЯ УЧЁТНАЯ ЗАПИСЬ АДМИНИСТРАТОРА\n"
            f" Логин:  {config.DEFAULT_ADMIN_USERNAME}\n"
            f" Пароль: {generated_password}\n"
            " Сохраните пароль — он больше нигде не будет показан.\n"
            " Сменить пароль можно после входа в панели управления.\n"
            "==================================================================\n"
        )
        logger.warning(banner)

    _ensure_vpn_servers_running()

    yield
    logger.info("Остановка приложения '%s'", config.APP_TITLE)


app = FastAPI(title=config.APP_TITLE, lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=auth.load_or_create_session_secret(),
    session_cookie=config.SESSION_COOKIE_NAME,
    max_age=config.SESSION_MAX_AGE_SECONDS,
    https_only=False,
)

app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")
app.include_router(router)
app.include_router(vpn_router)
app.include_router(log_router)
