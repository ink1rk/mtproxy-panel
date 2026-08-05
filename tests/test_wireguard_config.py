"""Проверяем PostUp wg-easy и клиентский формат как у wg-easy API."""
from __future__ import annotations

import unittest

import config
import wireguard_config as wc


class WireGuardConfigTests(unittest.TestCase):
    def test_wg_easy_post_up_matches_upstream(self) -> None:
        got = wc.wg_easy_post_up(
            subnet="10.8.0.0/24", listen_port=51820, device="eth0",
        )
        self.assertEqual(
            got,
            "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; "
            "iptables -A INPUT -p udp -m udp --dport 51820 -j ACCEPT; "
            "iptables -A FORWARD -i wg0 -j ACCEPT; "
            "iptables -A FORWARD -o wg0 -j ACCEPT",
        )

    def test_server_conf_uses_literal_wg0_and_psk(self) -> None:
        conf = wc.render_server_config(
            server_private_key="SERVERPRIV",
            listen_port=51820,
            subnet="10.66.0.0/24",
            peers=[
                wc.PeerForConfig(
                    name="phone",
                    public_key="CLIENTPUB",
                    allocated_ip="10.66.0.2",
                    preshared_key="PSKVALUE",
                )
            ],
        )
        # PostUp живёт вне conf (AppArmor) — в файле его быть не должно
        self.assertNotIn("PostUp", conf)
        self.assertNotIn("%i", conf)
        self.assertIn("PresharedKey = PSKVALUE", conf)
        self.assertIn("AllowedIPs = 10.66.0.2/32", conf)

    def test_client_matches_wg_easy_shape(self) -> None:
        self.assertEqual(config.WG_CLIENT_ALLOWED_IPS, "0.0.0.0/0")
        self.assertEqual(config.WG_CLIENT_MTU, 1280)
        conf = wc.render_client_config(
            client_private_key="CPRIV",
            client_allocated_ip="10.66.0.2",
            server_public_key="SPUB",
            server_endpoint_ip="72.56.92.22",
            server_listen_port=51820,
            dns="1.1.1.1",
            subnet="10.66.0.0/24",
            preshared_key="PSK",
        )
        self.assertIn("Address = 10.66.0.2/32", conf)
        self.assertIn("PresharedKey = PSK", conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0", conf)
        self.assertNotIn("::/0", conf)
        self.assertIn("MTU = 1280", conf)
        self.assertIn("PersistentKeepalive = 25", conf)
        self.assertIn("Endpoint = 72.56.92.22:51820", conf)

    def test_allocate_skips_used(self) -> None:
        ip = wc.allocate_next_ip("10.66.0.0/24", {"10.66.0.2", "10.66.0.3"})
        self.assertEqual(ip, "10.66.0.4")

    def test_default_subnet_matches_proven_path(self) -> None:
        self.assertEqual(config.WG_DEFAULT_SUBNET, "10.8.0.0/24")
        self.assertEqual(config.WG_DEFAULT_PORT, 443)
        self.assertEqual(config.WG_CLIENT_ADDRESS_PREFIX, "32")
        self.assertTrue(config.WG_AUTO_PROVISION)
        self.assertEqual(config.WG_DEFAULT_PEER_NAME, "iphone")


if __name__ == "__main__":
    unittest.main()
