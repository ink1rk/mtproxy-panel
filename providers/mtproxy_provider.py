"""
Адаптер MTProxy поверх service.ProxyService.

MTProxy концептуально отличается от WireGuard/VLESS: нет единого
"серверного конфига" — каждый прокси самодостаточен (свой порт, свой
секрет, свой Docker-контейнер). setup()/restart() тут не имеют смысла
в том виде, что у WG/VLESS, поэтому не переопределены (используются
безопасные дефолты из VpnProvider). Существует уже сейчас как
доказательство того, что интерфейс VpnProvider не завязан на
WireGuard/VLESS специфику, и как задел на будущую единую панель
"все провайдеры на одной странице".
"""
from __future__ import annotations

import config
from models import Proxy, ProviderClient
from providers.base import ProviderError, VpnProvider
from service import ProxyService, ProxyServiceError


def _to_client(proxy: Proxy) -> ProviderClient:
    return ProviderClient(
        id=str(proxy.id),
        name=proxy.container_name,
        created_at=proxy.created_at,
        config_text=proxy.tg_link,
        qr_filename=proxy.qr_filename,
        primary_label="Порт",
        primary_value=str(proxy.port),
        secondary_label="tg:// ссылка",
        secondary_value=proxy.tg_link,
    )


class MTProxyProvider(VpnProvider):
    key = "mtproxy"
    display_name = "MTProxy"
    icon = "bi-telegram"

    def __init__(self) -> None:
        try:
            self._service = ProxyService()
        except ProxyServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def is_configured(self) -> bool:
        return bool(self._service.list_proxies())

    def ensure_ready(self) -> ProviderClient | None:
        proxies = self._service.list_proxies()
        if proxies:
            return _to_client(proxies[0])
        try:
            # 443 — как у Telegram-рекомендаций: случайный высокий порт
            # многие мобильные сети режут ещё до TCP SYN.
            return _to_client(self._service.create_proxy(desired_port=config.MTPROXY_DEFAULT_HOST_PORT))
        except ProxyServiceError:
            try:
                return _to_client(self._service.create_proxy())
            except ProxyServiceError as exc:
                raise ProviderError(str(exc)) from exc

    def status(self) -> str:
        proxies = self._service.list_proxies()
        return proxies[0].status if proxies else "missing"

    def endpoint(self) -> str:
        proxies = self._service.list_proxies()
        return f"{proxies[0].ip}:{proxies[0].port}" if proxies else ""

    def list_clients(self) -> list[ProviderClient]:
        return [_to_client(p) for p in self._service.list_proxies()]

    def add_client(self, name: str) -> ProviderClient:
        del name  # MTProxy не именует прокси по запросу пользователя
        try:
            return _to_client(self._service.create_proxy())
        except ProxyServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def delete_client(self, client_id: str) -> None:
        try:
            self._service.delete_proxy(int(client_id))
        except ProxyServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def restart(self) -> None:
        return  # у каждого прокси свой restart policy на уровне Docker

    def reset(self) -> None:
        for proxy in self._service.list_proxies():
            self._service.delete_proxy(proxy.id)
