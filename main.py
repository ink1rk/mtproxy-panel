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
from routes import router


def configure_logging() -> None:
    """Настраивает логирование в файл (с ротацией) и в консоль."""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    formatter = logging.Formatter(config.LOG_FORMAT)

    file_handler = RotatingFileHandler(
        filename=config.LOG_FILE_PATH,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
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
