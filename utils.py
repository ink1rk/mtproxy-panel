"""
Утилитарные функции: поиск свободного порта, генерация секрета,
проверка TCP-порта, генерация QR-кода, определение публичного IP.

Никаких заглушек. Все функции полностью рабочие.
"""
from __future__ import annotations

import html
import logging
import secrets
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

import qrcode
from qrcode.image.pil import PilImage

import config

logger = logging.getLogger(__name__)


class NoFreePortError(RuntimeError):
    """Не удалось найти свободный TCP-порт в заданном диапазоне."""


class PublicIPLookupError(RuntimeError):
    """Не удалось определить публичный IP сервера."""


def is_port_free(port: int, host: str = "0.0.0.0") -> bool:
    """Проверяет, свободен ли TCP-порт для биндинга локально."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
        return True


def find_free_port(
    start: int = config.PORT_SCAN_RANGE_START,
    end: int = config.PORT_SCAN_RANGE_END,
) -> int:
    """
    Находит свободный TCP-порт в диапазоне [start, end], используя socket.
    Запрещено возвращать занятый порт.
    """
    candidates = list(range(start, end + 1))
    secrets.SystemRandom().shuffle(candidates)
    for port in candidates:
        if is_port_free(port):
            return port
    raise NoFreePortError(
        f"Не удалось найти свободный порт в диапазоне {start}-{end}"
    )


def generate_secret() -> str:
    """Генерирует криптостойкий базовый секрет MTProxy (32 hex-символа)."""
    return secrets.token_hex(config.SECRET_LENGTH_BYTES)


class InvalidTlsDomainError(ValueError):
    """Указанный домен для fake-TLS некорректен."""


class PortUnavailableError(RuntimeError):
    """Запрошенный пользователем порт занят или вне допустимого диапазона."""


def _domain_to_hex(domain: str) -> str:
    """Кодирует доменное имя в hex для встраивания в fake-TLS secret."""
    cleaned = domain.strip().lower()
    if not cleaned or len(cleaned) > 253:
        raise InvalidTlsDomainError("Некорректное доменное имя для fake-TLS")
    for label in cleaned.split("."):
        if not label or not all(ch.isalnum() or ch == "-" for ch in label):
            raise InvalidTlsDomainError(f"Некорректная часть домена: '{label}'")
    return cleaned.encode("ascii").hex()


def build_container_secret(base_secret: str, mode: str, tls_domain: str | None) -> str:
    """
    Строит secret, который будет передан в SECRET контейнера Docker.

    - classic: обычный 32-символьный hex-секрет без изменений.
    - dd: базовый секрет без изменений — режим 'dd' (random padding)
      определяется клиентом по префиксу secret'а в самой ссылке,
      серверу передаётся тот же базовый секрет.
    - ee: fake-TLS — контейнеру передаётся секрет вида
      'ee' + 32 hex символа + hex-encoded домен, как того требует
      официальный образ telegrammessenger/proxy.
    """
    if mode == config.SECRET_MODE_EE:
        if not tls_domain:
            raise InvalidTlsDomainError("Для режима 'ee' обязателен домен для fake-TLS")
        return f"ee{base_secret}{_domain_to_hex(tls_domain)}"
    return base_secret


def build_link_secret(base_secret: str, mode: str, tls_domain: str | None) -> str:
    """
    Строит secret, который будет показан пользователю в tg://, https:// ссылках и QR.
    """
    if mode == config.SECRET_MODE_DD:
        return f"dd{base_secret}"
    if mode == config.SECRET_MODE_EE:
        return build_container_secret(base_secret, mode, tls_domain)
    return base_secret


def validate_manual_port(port: int) -> int:
    """
    Проверяет, что запрошенный пользователем порт находится в допустимом
    диапазоне и свободен прямо сейчас. Бросает PortUnavailableError иначе.
    """
    if not (config.MIN_VALID_PORT <= port <= config.MAX_VALID_PORT):
        raise PortUnavailableError(
            f"Порт {port} вне допустимого диапазона "
            f"{config.MIN_VALID_PORT}-{config.MAX_VALID_PORT}"
        )
    if not is_port_free(port):
        raise PortUnavailableError(f"Порт {port} уже занят")
    return port


def generate_container_name() -> str:
    """Генерирует уникальное имя контейнера."""
    suffix = secrets.token_hex(4)
    return f"{config.CONTAINER_NAME_PREFIX}{suffix}"


def check_tcp_port_open(
    host: str,
    port: int,
    timeout: float = config.TCP_PORT_CHECK_TIMEOUT_SECONDS,
    interval: float = config.TCP_PORT_CHECK_INTERVAL_SECONDS,
) -> bool:
    """
    Опрашивает host:port до тех пор, пока порт не станет доступен
    для подключения снаружи, либо не истечёт timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(config.TCP_CONNECT_TIMEOUT_SECONDS)
            try:
                sock.connect((host, port))
                return True
            except OSError:
                time.sleep(interval)
    return False


def get_server_public_ip() -> str:
    """
    Определяет публичный IP сервера, последовательно пробуя несколько
    внешних сервисов. При недоступности сети падает обратно на локальный IP.
    """
    for url in config.PUBLIC_IP_LOOKUP_URLS:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
            with urllib.request.urlopen(
                request, timeout=config.PUBLIC_IP_LOOKUP_TIMEOUT_SECONDS
            ) as response:
                ip = response.read().decode("utf-8").strip()
                if ip:
                    return ip
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.warning("Не удалось получить публичный IP через %s: %s", url, exc)
            continue

    logger.warning("Все сервисы определения IP недоступны, использую локальный IP")
    return _get_local_ip_fallback()


def _get_local_ip_fallback() -> str:
    """Возвращает локальный IP как резервный вариант, если внешние сервисы недоступны."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except OSError as exc:
            raise PublicIPLookupError("Не удалось определить IP сервера") from exc


def build_tg_link(ip: str, port: int, secret: str) -> str:
    """Строит tg:// ссылку для подключения к прокси."""
    return f"tg://proxy?server={ip}&port={port}&secret={secret}"


def build_https_link(ip: str, port: int, secret: str) -> str:
    """Строит https://t.me/proxy ссылку для подключения к прокси."""
    return f"https://t.me/proxy?server={ip}&port={port}&secret={secret}"


def generate_qr_code(data: str, filename: str) -> Path:
    """
    Генерирует QR-код в формате PNG и сохраняет его в static/qr/.
    Возвращает путь к созданному файлу.
    """
    qr = qrcode.QRCode(
        box_size=config.QR_BOX_SIZE,
        border=config.QR_BORDER,
    )
    qr.add_data(data)
    qr.make(fit=True)
    image = qr.make_image(image_factory=PilImage, fill_color="black", back_color="white")

    output_path = config.QR_DIR / filename
    image.save(output_path)
    return output_path


def delete_qr_code(filename: str) -> None:
    """Удаляет файл QR-кода, если он существует."""
    qr_path = config.QR_DIR / filename
    if qr_path.exists():
        qr_path.unlink()


def escape_html(value: str) -> str:
    """Экранирует HTML-спецсимволы во входных данных."""
    return html.escape(value, quote=True)
