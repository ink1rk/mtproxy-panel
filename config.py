"""
Централизованная конфигурация приложения.
Все пути, таймауты, имена и настройки хранятся здесь.
"""
from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Базовые пути
# ---------------------------------------------------------------------------
BASE_DIR: Path = Path(__file__).resolve().parent

DATA_DIR: Path = BASE_DIR / "data"
LOG_DIR: Path = BASE_DIR / "logs"
STATIC_DIR: Path = BASE_DIR / "static"
QR_DIR: Path = STATIC_DIR / "qr"
TEMPLATES_DIR: Path = BASE_DIR / "templates"

DATABASE_PATH: Path = DATA_DIR / "mtproxy.db"
LOG_FILE_PATH: Path = LOG_DIR / "app.log"

# Создаём обязательные директории при импорте конфигурации.
for _directory in (DATA_DIR, LOG_DIR, STATIC_DIR, QR_DIR, TEMPLATES_DIR):
    _directory.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Docker / MTProxy
# ---------------------------------------------------------------------------
MTPROXY_DOCKER_IMAGE: str = "telegrammessenger/proxy:latest"
CONTAINER_NAME_PREFIX: str = "mtproxy_"
CONTAINER_INTERNAL_PORT: int = 443

DOCKER_CONTAINER_START_TIMEOUT_SECONDS: float = 20.0
DOCKER_CONTAINER_POLL_INTERVAL_SECONDS: float = 0.5
DOCKER_CONTAINER_REMOVE_TIMEOUT_SECONDS: float = 15.0

# ---------------------------------------------------------------------------
# Сеть
# ---------------------------------------------------------------------------
PORT_SCAN_RANGE_START: int = 10000
PORT_SCAN_RANGE_END: int = 60000
TCP_PORT_CHECK_TIMEOUT_SECONDS: float = 15.0
TCP_PORT_CHECK_INTERVAL_SECONDS: float = 0.5
TCP_CONNECT_TIMEOUT_SECONDS: float = 2.0

PUBLIC_IP_LOOKUP_URLS: tuple[str, ...] = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)
PUBLIC_IP_LOOKUP_TIMEOUT_SECONDS: float = 5.0

# ---------------------------------------------------------------------------
# Secret
# ---------------------------------------------------------------------------
SECRET_LENGTH_BYTES: int = 16  # secrets.token_hex(16) -> 32 hex символа

# ---------------------------------------------------------------------------
# QR
# ---------------------------------------------------------------------------
QR_BOX_SIZE: int = 8
QR_BORDER: int = 4

# ---------------------------------------------------------------------------
# Приложение
# ---------------------------------------------------------------------------
APP_HOST: str = "0.0.0.0"
APP_PORT: int = 8000
APP_TITLE: str = "MTProxy Control Panel"

# ---------------------------------------------------------------------------
# Логирование
# ---------------------------------------------------------------------------
LOG_MAX_BYTES: int = 5 * 1024 * 1024
LOG_BACKUP_COUNT: int = 5
LOG_FORMAT: str = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

# ---------------------------------------------------------------------------
# Ожидаемая схема таблицы proxies (для авто-миграции)
# ---------------------------------------------------------------------------
PROXIES_TABLE_NAME: str = "proxies"
EXPECTED_PROXIES_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "container_name": "TEXT NOT NULL UNIQUE",
    "ip": "TEXT NOT NULL",
    "port": "INTEGER NOT NULL",
    "secret": "TEXT NOT NULL",
    "tg_link": "TEXT NOT NULL",
    "https_link": "TEXT NOT NULL",
    "qr_filename": "TEXT NOT NULL",
    "status": "TEXT NOT NULL DEFAULT 'running'",
    "created_at": "TEXT NOT NULL",
}
