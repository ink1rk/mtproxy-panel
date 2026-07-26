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
SESSION_SECRET_PATH: Path = DATA_DIR / "session_secret.key"

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
MIN_VALID_PORT: int = 1
MAX_VALID_PORT: int = 65535

PUBLIC_IP_LOOKUP_URLS: tuple[str, ...] = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)
PUBLIC_IP_LOOKUP_TIMEOUT_SECONDS: float = 5.0

# ---------------------------------------------------------------------------
# Secret / режимы обфускации
# ---------------------------------------------------------------------------
SECRET_LENGTH_BYTES: int = 16  # secrets.token_hex(16) -> 32 hex символа

SECRET_MODE_CLASSIC: str = "classic"
SECRET_MODE_DD: str = "dd"          # random padding (anti-DPI)
SECRET_MODE_EE: str = "ee"          # fake-TLS под указанный домен
VALID_SECRET_MODES: tuple[str, ...] = (SECRET_MODE_CLASSIC, SECRET_MODE_DD, SECRET_MODE_EE)
DEFAULT_TLS_DOMAIN: str = "www.google.com"

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
# Аутентификация
# ---------------------------------------------------------------------------
SESSION_COOKIE_NAME: str = "mtproxy_session"
SESSION_MAX_AGE_SECONDS: int = 60 * 60 * 24 * 30  # 30 дней
PBKDF2_ALGORITHM: str = "sha256"
PBKDF2_ITERATIONS: int = 260_000
PBKDF2_SALT_BYTES: int = 16
DEFAULT_ADMIN_USERNAME: str = "admin"
GENERATED_PASSWORD_LENGTH_BYTES: int = 9  # -> 12 символов в urlsafe-base64
MIN_PASSWORD_LENGTH: int = 8

# ---------------------------------------------------------------------------
# Логирование
# ---------------------------------------------------------------------------
# Файл лога не копится бесконечно и не хранит архив старых версий (app.log.1,
# .2, ...) — по достижении LOG_MAX_BYTES он просто обрезается и пишется заново
# (см. main.py: TruncatingFileHandler).
LOG_MAX_BYTES: int = 10 * 1024 * 1024
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
    "container_secret": "TEXT NOT NULL",
    "secret_mode": "TEXT NOT NULL DEFAULT 'classic'",
    "tls_domain": "TEXT",
    "tg_link": "TEXT NOT NULL",
    "https_link": "TEXT NOT NULL",
    "qr_filename": "TEXT NOT NULL",
    "status": "TEXT NOT NULL DEFAULT 'running'",
    "created_at": "TEXT NOT NULL",
}

# ---------------------------------------------------------------------------
# Ожидаемая схема таблицы admin_users (для авто-миграции)
# ---------------------------------------------------------------------------
ADMIN_USERS_TABLE_NAME: str = "admin_users"
EXPECTED_ADMIN_USERS_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "username": "TEXT NOT NULL UNIQUE",
    "password_hash": "TEXT NOT NULL",
    "password_salt": "TEXT NOT NULL",
    "created_at": "TEXT NOT NULL",
}

# ---------------------------------------------------------------------------
# WireGuard VPN
# ---------------------------------------------------------------------------
WG_CONFIG_DIR: Path = DATA_DIR / "wireguard"
WG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

WG_DOCKER_IMAGE: str = "lscr.io/linuxserver/wireguard:latest"
WG_CONTAINER_NAME: str = "wg_server"
WG_INTERFACE_NAME: str = "wg0"
WG_DEFAULT_PORT: int = 51820
WG_DEFAULT_SUBNET: str = "10.66.0.0/24"
WG_SERVER_TUNNEL_IP: str = "10.66.0.1"
WG_DEFAULT_DNS: str = "1.1.1.1"
WG_KEEPALIVE_SECONDS: int = 25
DOCKER_WG_START_TIMEOUT_SECONDS: float = 20.0

WG_SERVER_CONFIG_TABLE_NAME: str = "wg_server_config"
EXPECTED_WG_SERVER_CONFIG_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY CHECK (id = 1)",
    "server_private_key": "TEXT NOT NULL",
    "server_public_key": "TEXT NOT NULL",
    "listen_port": "INTEGER NOT NULL",
    "subnet": "TEXT NOT NULL",
    "endpoint_ip": "TEXT NOT NULL",
    "dns": "TEXT NOT NULL",
    "created_at": "TEXT NOT NULL",
}

WG_PEERS_TABLE_NAME: str = "wg_peers"
EXPECTED_WG_PEERS_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "name": "TEXT NOT NULL UNIQUE",
    "private_key": "TEXT NOT NULL",
    "public_key": "TEXT NOT NULL",
    "allocated_ip": "TEXT NOT NULL UNIQUE",
    "config_text": "TEXT NOT NULL",
    "qr_filename": "TEXT NOT NULL",
    "created_at": "TEXT NOT NULL",
}

# ---------------------------------------------------------------------------
# Xray / VLESS+REALITY VPN
# ---------------------------------------------------------------------------
XRAY_CONFIG_DIR: Path = DATA_DIR / "xray"
XRAY_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

XRAY_DOCKER_IMAGE: str = "teddysun/xray:latest"
XRAY_CONTAINER_NAME: str = "xray_server"
XRAY_DEFAULT_PORT: int = 8443
# ВАЖНО: dest/serverName должны указывать на реальный сайт с TLS-сертификатом,
# чей TLS Certificate record укладывается в жёсткий лимит Xray-core (8192 байта,
# https://github.com/XTLS/Xray-core/issues/6356). www.microsoft.com ранее стоял
# тут по умолчанию, но у него из-за OCSP-stapling запись сертификата ~8273 байта —
# REALITY-хендшейк со ЛЮБЫМ клиентом гарантированно проваливался с ошибкой
# "processed invalid connection ... handshake did not complete successfully",
# независимо от корректности ключей/UUID/shortId. Проверено end-to-end реальным
# VLESS-клиентом: с www.cloudflare.com (маленький сертификат) туннель поднимается
# и передаёт трафик; с www.microsoft.com — нет, ни разу. Если меняете dest на
# что-то своё — выбирайте популярный сайт с TLS 1.3 и небольшим сертификатом
# (без длинных цепочек/OCSP-stapling), иначе получите ту же ошибку.
XRAY_DEFAULT_DEST: str = "www.cloudflare.com:443"
XRAY_DEFAULT_SERVER_NAMES: tuple[str, ...] = ("www.cloudflare.com",)
XRAY_FLOW: str = "xtls-rprx-vision"
DOCKER_XRAY_START_TIMEOUT_SECONDS: float = 20.0
XRAY_SHORT_ID_BYTES: int = 8  # -> 16 hex символов

XRAY_SERVER_CONFIG_TABLE_NAME: str = "xray_server_config"
EXPECTED_XRAY_SERVER_CONFIG_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY CHECK (id = 1)",
    "listen_port": "INTEGER NOT NULL",
    "dest": "TEXT NOT NULL",
    "server_names": "TEXT NOT NULL",
    "private_key": "TEXT NOT NULL",
    "public_key": "TEXT NOT NULL",
    "short_id": "TEXT NOT NULL",
    "created_at": "TEXT NOT NULL",
}

VLESS_CLIENTS_TABLE_NAME: str = "vless_clients"
EXPECTED_VLESS_CLIENTS_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "name": "TEXT NOT NULL UNIQUE",
    "client_uuid": "TEXT NOT NULL UNIQUE",
    "vless_link": "TEXT NOT NULL",
    "qr_filename": "TEXT NOT NULL",
    "created_at": "TEXT NOT NULL",
}
