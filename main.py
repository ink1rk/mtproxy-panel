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
    Полностью автоматический старт (без ручных шагов в UI):
      WireGuard — сервер + peer с QR
      Xray      — сервер + VLESS-клиент с QR
      MTProxy   — один прокси-контейнер, если ни одного ещё нет
    Ошибки только логируются — панель должна стартовать в любом случае.
    """
    try:
        from vpn_service import VpnServiceError, WireGuardService

        peer = WireGuardService().ensure_ready()
        if peer is not None:
            logger.info(
                "WireGuard готов: peer=%s ip=%s qr=%s",
                peer.name, peer.allocated_ip, peer.qr_filename,
            )
    except VpnServiceError as exc:
        logger.warning("WireGuard-сервер не удалось поднять при старте: %s", exc)
    except Exception:  # noqa: BLE001 — сбой VPN-автозапуска не должен ронять панель
        logger.exception("Неожиданная ошибка при автозапуске WireGuard")

    try:
        from vpn_service import VpnServiceError, XrayService

        client = XrayService().ensure_ready()
        if client is not None:
            logger.info("Xray готов: client=%s qr=%s", client.name, client.qr_filename)
    except VpnServiceError as exc:
        logger.warning("Xray-сервер не удалось поднять при старте: %s", exc)
    except Exception:  # noqa: BLE001
        logger.exception("Неожиданная ошибка при автозапуске Xray")

    try:
        import config
        from service import ProxyService, ProxyServiceError

        proxy_service = ProxyService()
        if not proxy_service.list_proxies():
            try:
                # 443 — как у Telegram-рекомендаций и проверенного рабочего
                # сервера: случайный высокий порт многие мобильные сети РФ
                # режут ещё до TCP SYN, даже когда порт открыт снаружи.
                proxy = proxy_service.create_proxy(desired_port=config.MTPROXY_DEFAULT_HOST_PORT)
            except ProxyServiceError as exc:
                logger.warning(
                    "MTProxy на порту %s не удался (%s) — пробую случайный порт",
                    config.MTPROXY_DEFAULT_HOST_PORT, exc,
                )
                proxy = proxy_service.create_proxy()
            logger.info(
                "MTProxy готов: container=%s port=%s", proxy.container_name, proxy.port,
            )
    except ProxyServiceError as exc:
        logger.warning("MTProxy не удалось создать при старте: %s", exc)
    except Exception:  # noqa: BLE001
        logger.exception("Неожиданная ошибка при автосоздании MTProxy")


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
