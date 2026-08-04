"""
Генерация config.json для Xray (VLESS + REALITY + Vision) и vless://
ссылок для клиентов. Чистые функции без побочных эффектов.

Формат config.json подтверждён по официальным примерам XTLS/Xray-examples
(VLESS-TCP-XTLS-Vision-REALITY). Поле flow опционально: если XRAY_FLOW
пустой — в config/ссылку оно не попадает (plain REALITY).
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
    Строит полный config.json для Xray-сервера с текущим списком клиентов.

    clients — список пар (client_uuid, name). Поле 'email' в клиенте Xray
    используется ИМЕННО для идентификации в access-логах (Xray подписывает
    строку лога значением email, если оно задано) — без него в логах видно
    только факт подключения, но не то, какой именно клиент его сделал.
    """
    return {
        # "info" — чтобы в docker-логах контейнера было видно реальные соединения
        # (accepted/dialing/domain) для просмотра в веб-логах панели; "warning"
        # такие записи полностью скрывает (это уровень ошибок, не событий).
        "log": {"loglevel": "info"},
        "inbounds": [
            {
                "listen": "0.0.0.0",
                "port": listen_port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {"id": client_uuid, "email": name, **({"flow": config.XRAY_FLOW} if config.XRAY_FLOW else {})}
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
                        # См. config.XRAY_MIN_CLIENT_VER — без явного значения
                        # свежий Xray-core режет обычные мобильные клиенты.
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
    """
    Строит vless:// ссылку для импорта клиентом (формат совместим
    с v2rayNG, NekoBox, Shadowrocket и т.д.).
    """
    params = (
        f"type=tcp&security=reality&pbk={public_key}&fp=chrome"
        f"&sni={server_name}&sid={short_id}"
    )
    if config.XRAY_FLOW:
        params += f"&flow={config.XRAY_FLOW}"
    remark_encoded = quote(remark, safe="")
    return f"vless://{client_uuid}@{server_ip}:{listen_port}?{params}#{remark_encoded}"
