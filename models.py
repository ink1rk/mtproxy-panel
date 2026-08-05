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
class ProviderClient:
    """
    Единая модель "клиента" для любого VPN/прокси-провайдера (WireGuard peer,
    VLESS client, MTProxy instance, будущие Shadowsocks/Hysteria2/...).

    Routes и шаблоны работают ТОЛЬКО с этой моделью и никогда не видят
    WireGuardPeer/VlessClient/Proxy напрямую — это держит UI независимым
    от того, какой именно протокол за ним стоит (см. providers/base.py).
    """

    id: str
    name: str
    created_at: str
    config_text: str
    qr_filename: str
    primary_label: str
    primary_value: str
    secondary_label: str = ""
    secondary_value: str = ""
    connection_label: str = ""
    traffic_label: str = ""

    @property
    def qr_url(self) -> str:
        return f"/static/qr/{self.qr_filename}"


@dataclass(frozen=True, slots=True)
class AdminUser:
    """Доменная модель администратора панели."""

    id: int
    username: str
    password_hash: str
    password_salt: str
    created_at: str


@dataclass(frozen=True, slots=True)
class WireGuardServerConfig:
    """Серверные настройки единственного WireGuard-инстанса панели."""

    server_private_key: str
    server_public_key: str
    listen_port: int
    subnet: str
    endpoint_ip: str
    dns: str
    created_at: str


@dataclass(frozen=True, slots=True)
class WireGuardPeer:
    """Доменная модель одного WireGuard-клиента (peer)."""

    id: int
    name: str
    private_key: str
    public_key: str
    allocated_ip: str
    config_text: str
    qr_filename: str
    created_at: str
    preshared_key: str = ""

    @property
    def qr_url(self) -> str:
        return f"/static/qr/{self.qr_filename}"


@dataclass(frozen=True, slots=True)
class XrayServerConfig:
    """Серверные настройки единственного Xray (VLESS+REALITY) инстанса панели."""

    listen_port: int
    dest: str
    server_names: str
    private_key: str
    public_key: str
    short_id: str
    created_at: str


@dataclass(frozen=True, slots=True)
class VlessClient:
    """Доменная модель одного VLESS-клиента."""

    id: int
    name: str
    client_uuid: str
    vless_link: str
    qr_filename: str
    created_at: str

    @property
    def qr_url(self) -> str:
        return f"/static/qr/{self.qr_filename}"
