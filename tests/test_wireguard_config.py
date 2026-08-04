"""Проверяем, что PostUp совпадает с default wg-easy v14 и клиент без ::/0."""
from __future__ import annotations

import unittest

import config
import wireguard_config as wc


class WireGuardConfigTests(unittest.TestCase):
    def test_wg_easy_post_up_matches_upstream(self) -> None:
        # https://github.com/wg-easy/wg-easy/blob/v14/src/config.js
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

    def test_server_conf_uses_literal_wg0_not_percent_i(self) -> None:
        conf = wc.render_server_config(
            server_private_key="SERVERPRIV",
            listen_port=51820,
            subnet="10.66.0.0/24",
            peers=[
                wc.PeerForConfig(
                    name="phone", public_key="CLIENTPUB", allocated_ip="10.66.0.2",
                )
            ],
        )
        post_up_line = next(line for line in conf.splitlines() if line.startswith("PostUp"))
        self.assertIn("FORWARD -i wg0", post_up_line)
        self.assertIn("FORWARD -o wg0", post_up_line)
        self.assertNotIn("%i", post_up_line)
        self.assertIn("MASQUERADE", post_up_line)
        self.assertIn("--dport 51820", post_up_line)
        self.assertIn("AllowedIPs = 10.66.0.2/32", conf)
        self.assertIn("Address = 10.66.0.1/24", conf)

    def test_client_ipv4_only_allowed_ips(self) -> None:
        self.assertEqual(config.WG_CLIENT_ALLOWED_IPS, "0.0.0.0/0")
        conf = wc.render_client_config(
            client_private_key="CPRIV",
            client_allocated_ip="10.66.0.2",
            server_public_key="SPUB",
            server_endpoint_ip="72.56.92.22",
            server_listen_port=51820,
            dns="1.1.1.1",
        )
        self.assertIn("AllowedIPs = 0.0.0.0/0", conf)
        self.assertNotIn("::/0", conf)
        self.assertIn("Address = 10.66.0.2/32", conf)
        self.assertIn("MTU = 1420", conf)
        self.assertIn("PersistentKeepalive = 25", conf)

    def test_allocate_skips_used(self) -> None:
        ip = wc.allocate_next_ip("10.66.0.0/24", {"10.66.0.2", "10.66.0.3"})
        self.assertEqual(ip, "10.66.0.4")


if __name__ == "__main__":
    unittest.main()
