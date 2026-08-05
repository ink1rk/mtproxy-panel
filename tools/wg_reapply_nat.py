#!/usr/bin/env python3
"""
Переприменяет WireGuard NAT/FORWARD после рестарта Docker
(Docker чистит DOCKER-USER/FORWARD при своём старте).

Заменяет собой прежний bash-хелпер /usr/local/sbin/mtproxy-wg-nat.sh —
вызывается тем же systemd-юнитом (mtproxy-wg-forward.service,
PartOf=docker.service), но делает всё через код панели, без единой
shell-строки.

Использование: venv/bin/python tools/wg_reapply_nat.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpn_service import WireGuardService  # noqa: E402


def main() -> int:
    try:
        service = WireGuardService()
    except Exception as exc:  # noqa: BLE001
        print(f"WireGuardService init failed: {exc}")
        return 0  # не роняем systemd-юнит, если WG ещё не настроен

    server_config = service.get_server_config()
    if server_config is None:
        print("WireGuard ещё не настроен — нечего переприменять")
        return 0

    service.ensure_running_if_configured()
    print(f"NAT/FORWARD переприменены: subnet={server_config.subnet} port={server_config.listen_port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
