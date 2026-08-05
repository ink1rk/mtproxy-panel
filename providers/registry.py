"""
Реестр провайдеров: единственное место, где перечислены конкретные
реализации. Добавление нового протокола = один новый файл
providers/<name>_provider.py + одна строка здесь.
"""
from __future__ import annotations

from providers.base import VpnProvider
from providers.mtproxy_provider import MTProxyProvider
from providers.vless_provider import VlessProvider
from providers.wireguard_provider import WireGuardProvider

_FACTORIES: dict[str, type[VpnProvider]] = {
    "wireguard": WireGuardProvider,
    "vless": VlessProvider,
    "mtproxy": MTProxyProvider,
}


def get_provider(key: str) -> VpnProvider:
    factory = _FACTORIES.get(key)
    if factory is None:
        raise KeyError(f"Неизвестный VPN-провайдер: {key!r}")
    return factory()


def list_providers() -> list[str]:
    return list(_FACTORIES.keys())
