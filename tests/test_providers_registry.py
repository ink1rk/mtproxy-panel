"""Проверяем реестр провайдеров и общий интерфейс (без реального хоста)."""
from __future__ import annotations

import unittest

from providers.base import VpnProvider
from providers.mtproxy_provider import MTProxyProvider
from providers.registry import get_provider, list_providers
from providers.vless_provider import VlessProvider
from providers.wireguard_provider import WireGuardProvider


class ProviderRegistryTests(unittest.TestCase):
    def test_known_providers_registered(self) -> None:
        self.assertEqual(set(list_providers()), {"wireguard", "vless", "mtproxy"})

    def test_unknown_provider_raises(self) -> None:
        with self.assertRaises(KeyError):
            get_provider("shadowsocks")

    def test_all_providers_implement_common_interface(self) -> None:
        for cls in (WireGuardProvider, VlessProvider, MTProxyProvider):
            self.assertTrue(issubclass(cls, VpnProvider))
            for method in (
                "is_configured", "ensure_ready", "status", "endpoint",
                "list_clients", "add_client", "delete_client", "restart", "reset",
            ):
                self.assertTrue(callable(getattr(cls, method, None)), f"{cls.__name__}.{method}")
            self.assertTrue(cls.key)
            self.assertTrue(cls.display_name)


if __name__ == "__main__":
    unittest.main()
