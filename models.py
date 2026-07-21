"""
Доменные модели приложения.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Proxy:
    """Доменная модель MTProxy-инстанса."""

    id: int
    container_name: str
    ip: str
    port: int
    secret: str
    container_secret: str
    secret_mode: str
    tls_domain: str | None
    tg_link: str
    https_link: str
    qr_filename: str
    status: str
    created_at: str

    @property
    def qr_url(self) -> str:
        """Публичный URL до QR-изображения, относительно /static."""
        return f"/static/qr/{self.qr_filename}"

    @property
    def secret_mode_label(self) -> str:
        """Человекочитаемая подпись режима секрета."""
        labels = {
            "classic": "Обычный",
            "dd": "dd (anti-DPI)",
            "ee": "ee (fake-TLS)",
        }
        return labels.get(self.secret_mode, self.secret_mode)


@dataclass(frozen=True, slots=True)
class AdminUser:
    """Доменная модель администратора панели."""

    id: int
    username: str
    password_hash: str
    password_salt: str
    created_at: str
