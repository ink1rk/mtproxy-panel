"""
Точка входа приложения: настройка логирования, инициализация БД,
монтирование статики и подключение роутов.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

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
    yield
    logger.info("Остановка приложения '%s'", config.APP_TITLE)


app = FastAPI(title=config.APP_TITLE, lifespan=lifespan)

app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")
app.include_router(router)
