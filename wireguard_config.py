"""
Генерация текстовых конфигов WireGuard: серверного wg0.conf и клиентских .conf.

NAT НЕ в PostUp: внешний скрипт ломал wg-quick (Permission denied → rollback).
Маршрутизацию применяет firewall_manager после поднятия интерфейса.
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


def render_server_config(
    *,
    server_private_key: str,
    listen_port: int,
    subnet: str,
    peers: list[PeerForConfig],
) -> str:
    """
    /etc/wireguard/wg0.conf для native wg-quick@.

    Без PostUp/PostDown — только Interface + Peers. Иначе падение PostUp
    откатывает весь wg0 (ip link delete). NAT делает FirewallManager.
    """
    _, prefix = _subnet_base_and_prefix(subnet)
    lines = [
        "[Interface]",
        f"PrivateKey = {server_private_key}",
        f"Address = {server_tunnel_address(subnet)}/{prefix}",
        f"ListenPort = {listen_port}",
        f"MTU = {config.WG_CLIENT_MTU}",
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
    """
    Клиентский .conf для iOS/Android WireGuard.

    AllowedIPs = 0.0.0.0/0 (весь IPv4 через VPN).
    Без ::/0 — на сервере нет IPv6 NAT, иначе blackhole на iPhone.
    """
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
