"""
Генерация config.json для Xray (VLESS + REALITY + Vision) и vless:// ссылок.
"""
from __future__ import annotations

from urllib.parse import quote

import config


def render_server_config(
    *,
    listen_port: int,
    dest: str,
    server_names: list[str],
    private_key: str,
    short_id: str,
    clients: list[tuple[str, str]],
) -> dict:
    """
    Полный config.json для Xray-сервера.

    clients — список пар (client_uuid, name); email используется в access-логах.

    Транспорт XHTTP (не голый TCP+Vision): данные идут отдельными
    HTTP-запросами вместо одного хрупкого TCP-потока с TLS-in-TLS.
    На нестабильных/мобильных сетях raw TCP+REALITY+Vision у части
    пользователей стабильно давал "failed to read client hello" —
    сервер был доказанно исправен (внешний тестовый клиент проходил
    20/20), проблема именно в устойчивости сырого TCP-потока на
    конкретном сетевом пути. XHTTP переживает потерю/повтор отдельных
    HTTP-запросов гораздо лучше, чем один непрерывный TCP-поток —
    именно для этого он и был добавлен в Xray-core.
    """
    return {
        "log": {"loglevel": "info"},
        "inbounds": [
            {
                "listen": "0.0.0.0",
                "port": listen_port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {"id": client_uuid, "email": name}
                        for client_uuid, name in clients
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "xhttp",
                    "xhttpSettings": {"path": config.XRAY_XHTTP_PATH},
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": dest,
                        "xver": 0,
                        "serverNames": server_names,
                        "privateKey": private_key,
                        "shortIds": [short_id],
                        "minClientVer": config.XRAY_MIN_CLIENT_VER,
                    },
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            }
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
    }


def build_vless_link(
    *,
    client_uuid: str,
    server_ip: str,
    listen_port: int,
    public_key: str,
    short_id: str,
    server_name: str,
    remark: str,
) -> str:
    """vless:// ссылка для v2rayNG / NekoBox / Shadowrocket (транспорт XHTTP)."""
    path_encoded = quote(config.XRAY_XHTTP_PATH, safe="")
    params = (
        f"encryption=none&security=reality&pbk={public_key}&fp=chrome"
        f"&sni={server_name}&sid={short_id}"
        f"&type=xhttp&path={path_encoded}&mode=auto"
    )
    remark_encoded = quote(remark, safe="")
    return f"vless://{client_uuid}@{server_ip}:{listen_port}?{params}#{remark_encoded}"
