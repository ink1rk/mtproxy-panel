"""
Генерация конфигов WireGuard.

PostUp/PostDown — default из wg-easy v14.
Клиентский формат — как отдаёт wg-easy API:
  Address = <ip>/<subnet-prefix>   (не /32)
  PresharedKey = ...
  MTU = 1280
  AllowedIPs = 0.0.0.0/0
  PersistentKeepalive = 25
"""
from __future__ import annotations

from dataclasses import dataclass

import config


@dataclass(frozen=True, slots=True)
class PeerForConfig:
    name: str
    public_key: str
    allocated_ip: str
    preshared_key: str = ""


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
    network_cidr = subnet if "/" in subnet else f"{subnet}/24"
    return (
        f"iptables -t nat -A POSTROUTING -s {network_cidr} -o {device} -j MASQUERADE; "
        f"iptables -A INPUT -p udp -m udp --dport {listen_port} -j ACCEPT; "
        f"iptables -A FORWARD -i wg0 -j ACCEPT; "
        f"iptables -A FORWARD -o wg0 -j ACCEPT"
    )


def wg_easy_post_down(*, subnet: str, listen_port: int, device: str) -> str:
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
    """
    Серверный conf без PostUp/PostDown.
    На Ubuntu AppArmor ломает iptables в PostUp (если iptables→legacy);
    NAT ставит WireGuardManager._ensure_nat вне профиля.
    """
    _, prefix = _subnet_base_and_prefix(subnet)
    del wan_device  # reserved for callers / future
    lines = [
        "[Interface]",
        f"PrivateKey = {server_private_key}",
        f"Address = {server_tunnel_address(subnet)}/{prefix}",
        f"ListenPort = {listen_port}",
        # MTU только на клиенте: AppArmor wg-quick//ip иногда
        # даёт RTNETLINK Permission denied на `ip link set mtu`.
        "",
    ]
    for peer in peers:
        lines.extend(
            [
                f"# {peer.name}",
                "[Peer]",
                f"PublicKey = {peer.public_key}",
            ]
        )
        if peer.preshared_key:
            lines.append(f"PresharedKey = {peer.preshared_key}")
        lines.extend(
            [
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
    subnet: str = config.WG_DEFAULT_SUBNET,
    preshared_key: str = "",
) -> str:
    """Клиент: Address /32, PSK, MTU, IPv4-only AllowedIPs."""
    del subnet  # prefix фиксирован — см. WG_CLIENT_ADDRESS_PREFIX
    prefix = config.WG_CLIENT_ADDRESS_PREFIX
    lines = [
        "[Interface]",
        f"PrivateKey = {client_private_key}",
        f"Address = {client_allocated_ip}/{prefix}",
        f"DNS = {dns}",
        f"MTU = {config.WG_CLIENT_MTU}",
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
    ]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines.extend(
        [
            f"AllowedIPs = {config.WG_CLIENT_ALLOWED_IPS}",
            f"PersistentKeepalive = {config.WG_KEEPALIVE_SECONDS}",
            f"Endpoint = {server_endpoint_ip}:{server_listen_port}",
            "",
        ]
    )
    return "\n".join(lines)


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
