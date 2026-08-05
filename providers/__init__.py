"""
Единый интерфейс VPN/прокси-провайдеров (WireGuard, VLESS, MTProxy, и
любой будущий протокол — Shadowsocks, Hysteria2, OpenVPN, AmneziaWG).

Routes/шаблоны зависят ТОЛЬКО от providers.base.VpnProvider и
models.ProviderClient — никогда от конкретных *_manager.py/*_service.py.
Добавление нового протокола = один новый файл providers/<name>_provider.py
+ регистрация в providers/registry.py, без изменений в routes.py/шаблонах.
"""
from __future__ import annotations

from providers.base import VpnProvider
from providers.registry import get_provider, list_providers

__all__ = ["VpnProvider", "get_provider", "list_providers"]
