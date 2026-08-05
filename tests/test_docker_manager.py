"""Проверяем детектор ошибки Docker nat/DOCKER chain (см. docker_iptables.py)."""
from __future__ import annotations

import unittest

from docker_manager import _looks_like_docker_chain_error


class DockerChainErrorDetectionTests(unittest.TestCase):
    def test_detects_real_world_error_message(self) -> None:
        message = (
            "500 Server Error for http+docker://localhost/v1.55/containers/"
            "abc123/start: Internal Server Error (\"failed to set up container "
            "networking: driver failed programming external connectivity on "
            "endpoint mtproxy_ed5af3a2: Unable to enable DNAT rule:  "
            "(iptables failed: iptables --wait -t nat -A DOCKER -p tcp -d 0/0 "
            "--dport 35918 -j DNAT --to-destination 172.17.0.2:443 ! -i docker0: "
            "iptables: No chain/target/match by that name.\n (exit status 1))\")"
        )
        self.assertTrue(_looks_like_docker_chain_error(RuntimeError(message)))

    def test_ignores_unrelated_errors(self) -> None:
        self.assertFalse(_looks_like_docker_chain_error(RuntimeError("port already in use")))
        self.assertFalse(_looks_like_docker_chain_error(RuntimeError("image not found")))


if __name__ == "__main__":
    unittest.main()
