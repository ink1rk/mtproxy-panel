"""
Генерация конфигов WireGuard.

PostUp/PostDown — ДОСЛОВНО default из wg-easy v14 src/config.js:
  https://github.com/wg-easy/wg-easy/blob/v14/src/config.js

  iptables -t nat -A POSTROUTING -s <subnet> -o <device> -j MASQUERADE;
  iptables -A INPUT -p udp -m udp --dport <port> -j ACCEPT;
  iptables -A FORWARD -i wg0 -j ACCEPT;
  iptables -A FORWARD -o wg0 -j ACCEPT;

Интерфейс в FORWARD — литерал wg0 (не %i):
  AskUbuntu #1354741 — %i ломает NAT («handshake ok, no internet»).

Клиент AllowedIPs только IPv4 (0.0.0.0/0):
  wg-easy#562 — ::/0 без IPv6-NAT = «подключён, интернета нет».
"""
from __future__ import annotations

from dataclasses import dataclass

import config


@dataclass(frozen=True, slots=True)
class PeerForConfig:
    name: str
    public_key: str
    allocated_ip: str


def _subnet_base_and_prefix(subnet: str) -> tuple[str, str]:
    network_part, _, prefix = subnet.partition("/")
    octets = network_part.split(".")
    if len(octets) != 4:
        raise ValueError(f"Некорректная подсеть: {subnet!r}")
    return ".".join(octets[:3]), (prefix or "24")


def server_tunnel_address(subnet: str) -> str:
    base, _ = _subnet_base_and_prefix(subnet)
    return f"{base}.1"


def wg_easy_post_up(*, subnet: str, listen_port: int, device: str) -> str:
    """Default WG_POST_UP из wg-easy v14 (одной строкой, без кавычек)."""
    network_cidr = subnet if "/" in subnet else f"{subnet}/24"
    return (
        f"iptables -t nat -A POSTROUTING -s {network_cidr} -o {device} -j MASQUERADE; "
        f"iptables -A INPUT -p udp -m udp --dport {listen_port} -j ACCEPT; "
        f"iptables -A FORWARD -i wg0 -j ACCEPT; "
        f"iptables -A FORWARD -o wg0 -j ACCEPT"
    )


def wg_easy_post_down(*, subnet: str, listen_port: int, device: str) -> str:
    """Default WG_POST_DOWN из wg-easy v14."""
    network_cidr = subnet if "/" in subnet else f"{subnet}/24"
    return (
        f"iptables -t nat -D POSTROUTING -s {network_cidr} -o {device} -j MASQUERADE; "
        f"iptables -D INPUT -p udp -m udp --dport {listen_port} -j ACCEPT; "
        f"iptables -D FORWARD -i wg0 -j ACCEPT; "
        f"iptables -D FORWARD -o wg0 -j ACCEPT"
    )


def render_server_config(
    *,
    server_private_key: str,
    listen_port: int,
    subnet: str,
    peers: list[PeerForConfig],
    wan_device: str | None = None,
) -> str:
    """wg0.conf для linuxserver bare mode с PostUp как у wg-easy."""
    _, prefix = _subnet_base_and_prefix(subnet)
    device = wan_device or config.WG_DOCKER_WAN_IFACE
    post_up = wg_easy_post_up(subnet=subnet, listen_port=listen_port, device=device)
    post_down = wg_easy_post_down(subnet=subnet, listen_port=listen_port, device=device)
    lines = [
        "[Interface]",
        f"PrivateKey = {server_private_key}",
        f"Address = {server_tunnel_address(subnet)}/{prefix}",
        f"ListenPort = {listen_port}",
        f"MTU = {config.WG_CLIENT_MTU}",
        f"PostUp = {post_up}",
        f"PostDown = {post_down}",
        "",
    ]
    for peer in peers:
        lines.extend(
            [
                f"# {peer.name}",
                "[Peer]",
                f"PublicKey = {peer.public_key}",
                f"AllowedIPs = {peer.allocated_ip}/32",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_client_config(
    *,
    client_private_key: str,
    client_allocated_ip: str,
    server_public_key: str,
    server_endpoint_ip: str,
    server_listen_port: int,
    dns: str,
) -> str:
    """Клиент iOS/Android. Address /32, AllowedIPs только IPv4."""
    return "\n".join(
        [
            "[Interface]",
            f"PrivateKey = {client_private_key}",
            f"Address = {client_allocated_ip}/32",
            f"DNS = {dns}",
            f"MTU = {config.WG_CLIENT_MTU}",
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
            f"Endpoint = {server_endpoint_ip}:{server_listen_port}",
            f"AllowedIPs = {config.WG_CLIENT_ALLOWED_IPS}",
            f"PersistentKeepalive = {config.WG_KEEPALIVE_SECONDS}",
            "",
        ]
    )


def allocate_next_ip(subnet: str, used_ips: set[str]) -> str:
    network_part = subnet.split("/")[0]
    octets = network_part.split(".")
    if len(octets) != 4:
        raise ValueError(f"Некорректная подсеть: {subnet!r}")
    base = ".".join(octets[:3])
    for host_octet in range(2, 255):
        candidate = f"{base}.{host_octet}"
        if candidate not in used_ips:
            return candidate
    raise RuntimeError(f"В подсети {subnet} закончились свободные IP-адреса")
