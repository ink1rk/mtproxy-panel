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
# Порт на хосте для авто-созданного (первого) прокси. 443 — как в
# официальных рекомендациях Telegram и на проверенном годами рабочем
# сервере: многие сети (особенно мобильные операторы РФ) пропускают
# только стандартные веб-порты и режут произвольные высокие TCP-порты
# ещё до TCP SYN — именно это наблюдалось со случайным портом.
MTPROXY_DEFAULT_HOST_PORT: int = 443

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
# WireGuard VPN — native wg-quick@wg0 + PostUp как wg-easy
# ---------------------------------------------------------------------------
WG_CONFIG_DIR: Path = DATA_DIR / "wireguard"
WG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Legacy Docker (больше не используется; manager делает docker rm -f).
WG_DOCKER_IMAGE: str = "lscr.io/linuxserver/wireguard:latest"
WG_CONTAINER_NAME: str = "wg_server"
WG_INTERFACE_NAME: str = "wg0"
WG_SYSTEMD_UNIT: str = "wg-quick@wg0.service"
WG_DEFAULT_PORT: int = 443
WG_DEFAULT_SUBNET: str = "10.8.0.0/24"
# 8.8.8.8 первым: на части сетей 1.1.1.1 сам по себе нестабилен/фильтруется.
# Совпадает с проверенным годами рабочим wg-easy сервером пользователя.
WG_DEFAULT_DNS: str = "8.8.8.8, 1.1.1.1"
# Авто: при старте панели поднять WG + создать peer с QR (без ручных шагов).
WG_AUTO_PROVISION: bool = True
WG_DEFAULT_PEER_NAME: str = "iphone"
WG_KEEPALIVE_SECONDS: int = 25
# Без явного MTU в клиентском конфиге — как в проверенном годами рабочем
# wg-easy (клиент/ОС сами подбирают MTU). Раньше форсировали 1280 —
# на реальных телефонах (WiFi и мобильный интернет) это совпадало с
# "handshake есть, трафика почти нет"; референсный сервер MTU не трогает.
WG_START_TIMEOUT_SECONDS: float = 45.0
WG_INTERFACE_TIMEOUT_SECONDS: float = 60.0
# WAN для MASQUERADE; runtime ещё раз определяет через default route.
WG_DOCKER_WAN_IFACE: str = "eth0"
WG_NETWORK_MODE: str = "native"

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
    "preshared_key": "TEXT NOT NULL DEFAULT ''",
    "allocated_ip": "TEXT NOT NULL UNIQUE",
    "config_text": "TEXT NOT NULL",
    "qr_filename": "TEXT NOT NULL",
    "created_at": "TEXT NOT NULL",
}

# ---------------------------------------------------------------------------
# Xray / VLESS+REALITY VPN (native binary + systemd)
# ---------------------------------------------------------------------------
XRAY_CONFIG_DIR: Path = DATA_DIR / "xray"
XRAY_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

XRAY_BINARY_PATH: str = "/usr/local/bin/xray"
XRAY_SYSTEM_CONF_PATH: str = "/usr/local/etc/xray/config.json"
XRAY_SYSTEMD_UNIT: str = "xray.service"
XRAY_SYSTEMD_UNIT_PATH: str = "/etc/systemd/system/xray.service"
XRAY_DEFAULT_PORT: int = 8443
# ВАЖНО: dest/serverName — сайт с небольшим TLS-сертификатом (<8192 байт
# Certificate record). www.cloudflare.com проверен; www.microsoft.com — нет.
XRAY_DEFAULT_DEST: str = "www.cloudflare.com:443"
XRAY_DEFAULT_SERVER_NAMES: tuple[str, ...] = ("www.cloudflare.com",)
# Авто: при старте панели поднять Xray + создать клиента (без ручных шагов).
XRAY_AUTO_PROVISION: bool = True
XRAY_DEFAULT_CLIENT_NAME: str = "main"
# Транспорт XHTTP вместо голого TCP+Vision: данные идут отдельными HTTP-
# запросами, что заметно устойчивее к потере пакетов на плохих мобильных
# сетях, где один непрерывный TCP-поток с REALITY стабильно рвался
# ("failed to read client hello") при доказанно исправном сервере.
XRAY_XHTTP_PATH: str = "/xhttp"
# Официальный режим VLESS+REALITY + Vision — используется только для
# транспорта tcp (не применяется к xhttp, оставлен для истории/отладки).
XRAY_FLOW: str = "xtls-rprx-vision"
# Xray-core >= 26.7.11 при пустом minClientVer подставляет 26.3.27 и режет
# обычные мобильные клиенты (TLS «ок», прокси-байт 0). Явно держим низкий порог.
XRAY_MIN_CLIENT_VER: str = "1.0.0"
XRAY_START_TIMEOUT_SECONDS: float = 20.0
XRAY_SHORT_ID_BYTES: int = 8  # -> 16 hex символов

# ---------------------------------------------------------------------------
# Host firewall / sysctl (nftables)
# ---------------------------------------------------------------------------
NFT_TABLE_NAME: str = "mtproxy-panel"
NFT_RULES_PATH: str = "/etc/nftables.d/mtproxy-panel.nft"
SYSCTL_FORWARD_PATH: str = "/etc/sysctl.d/99-mtproxy-panel-forward.conf"
# Полный default route (IPv4 + IPv6) — ровно как у проверенного годами
# рабочего wg-easy сервера (41+ ГБ трафика с реального iPhone). Split
# 0.0.0.0/1+128.0.0.0/1 пробовали для Windows — не решило проблему и
# не нужно: официальные клиенты (Windows/iOS/Android) сами исключают
# маршрут до Endpoint при получении литерального 0.0.0.0/0.
WG_CLIENT_ALLOWED_IPS: str = "0.0.0.0/0, ::/0"
WG_CLIENT_ADDRESS_PREFIX: str = "24"

# Ротация docker-логов только для MTProxy-контейнеров.
DOCKER_LOG_CONFIG: dict = {
    "type": "json-file",
    "config": {
        "max-size": "10m",
        "max-file": "1",
    },
}

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
