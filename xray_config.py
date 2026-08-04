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
                        {
                            "id": client_uuid,
                            "email": name,
                            **({"flow": config.XRAY_FLOW} if config.XRAY_FLOW else {}),
                        }
                        for client_uuid, name in clients
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
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
    """vless:// ссылка для v2rayNG / NekoBox / Shadowrocket."""
    params = (
        f"type=tcp&security=reality&pbk={public_key}&fp=chrome"
        f"&sni={server_name}&sid={short_id}"
    )
    if config.XRAY_FLOW:
        params += f"&flow={config.XRAY_FLOW}"
    remark_encoded = quote(remark, safe="")
    return f"vless://{client_uuid}@{server_ip}:{listen_port}?{params}#{remark_encoded}"
