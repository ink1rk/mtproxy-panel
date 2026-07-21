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
    tg_link: str
    https_link: str
    qr_filename: str
    status: str
    created_at: str

    @property
    def qr_url(self) -> str:
        """Публичный URL до QR-изображения, относительно /static."""
        return f"/static/qr/{self.qr_filename}"
