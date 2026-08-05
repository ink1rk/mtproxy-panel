"""Проверяем человекочитаемые вердикты diagnose_peer (без реального хоста)."""
from __future__ import annotations

import unittest

import vpn_health as vh


class DiagnosePeerTests(unittest.TestCase):
    def test_never_connected(self) -> None:
        d = vh.diagnose_peer(name="iphone", handshake_epoch=0, rx_bytes=0, tx_bytes=0)
        self.assertFalse(d.has_handshake)
        self.assertEqual(d.severity, "error")
        self.assertIn("ни разу не подключался", d.verdict)

    def test_handshake_but_no_real_traffic(self) -> None:
        d = vh.diagnose_peer(
            name="iphone", handshake_epoch=1_700_000_000, rx_bytes=1044, tx_bytes=3804,
        )
        self.assertTrue(d.has_handshake)
        self.assertEqual(d.severity, "warning")
        self.assertIn("keepalive", d.verdict)

    def test_traffic_flowing_normally(self) -> None:
        d = vh.diagnose_peer(
            name="iphone", handshake_epoch=1_700_000_000, rx_bytes=5_000_000, tx_bytes=2_000_000,
        )
        self.assertEqual(d.severity, "ok")


if __name__ == "__main__":
    unittest.main()
