"""
Генерация текстовых конфигов WireGuard: серверного wg0.conf (со всеми
peer-ами) и клиентских .conf файлов (по одному на peer, для скачивания
и QR-кода).

Чистые функции без побочных эффектов — не трогают диск и Docker,
поэтому полностью тестируются без реального контейнера.
"""
from __future__ import annotations

from dataclasses import dataclass

import config


@dataclass(frozen=True, slots=True)
class PeerForConfig:
    """Минимальный набор полей peer-а, нужный для рендера серверного конфига."""

    name: str
    public_key: str
    allocated_ip: str


def _subnet_base_and_prefix(subnet: str) -> tuple[str, str]:
    """Разбирает '10.66.0.0/24' -> ('10.66.0', '24'). Дефолт префикса — '24'."""
    network_part, _, prefix = subnet.partition("/")
    octets = network_part.split(".")
    if len(octets) != 4:
        raise ValueError(f"Некорректная подсеть: {subnet!r}")
    return ".".join(octets[:3]), (prefix or "24")


def server_tunnel_address(subnet: str) -> str:
    """
    Адрес самого сервера в туннеле — всегда '.1' указанной подсети.
    ВАЖНО: ранее здесь был захардкожен config.WG_SERVER_TUNNEL_IP ('10.66.0.1')
    независимо от подсети, которую вводит администратор при настройке — если
    он указывал любую другую подсеть, сервер поднимался с адресом ИЗ ЧУЖОЙ
    подсети, а выделяемые пирам IP (allocate_next_ip, ниже) были из подсети,
    которую он реально ввёл. Peer никогда не мог достучаться до сервера,
    потому что на кону разные /24-сети — тот же класс проблем, что и с
    "чужим" ключом при баге PEERS=0 (см. историю коммитов), просто в другом
    месте. Теперь адрес сервера всегда согласован с фактической подсетью.
    """
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
    Строит содержимое server-side wg0.conf: один [Interface] и по одному
    [Peer] блоку на каждого зарегистрированного клиента.

    PostUp/PostDown — только простые iptables-команды.
    Сложный PostUp (sysctl / `iptables -C || -A`) на части образов linuxserver
    зависал внутри wg-quick → интерфейс не поднимался → страница setup в
    панели «висела». Надёжный NAT дожимает ensure_nat_rules() после старта.
    """
    _, prefix = _subnet_base_and_prefix(subnet)
    network_cidr = subnet if "/" in subnet else f"{subnet}/{prefix}"
    lines = [
        "[Interface]",
        f"PrivateKey = {server_private_key}",
        f"Address = {server_tunnel_address(subnet)}/{prefix}",
        f"ListenPort = {listen_port}",
        "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; "
        "iptables -A FORWARD -o wg0 -j ACCEPT; "
        f"iptables -t nat -A POSTROUTING -s {network_cidr} -j MASQUERADE",
        "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; "
        "iptables -D FORWARD -o wg0 -j ACCEPT; "
        f"iptables -t nat -D POSTROUTING -s {network_cidr} -j MASQUERADE",
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
    """Строит содержимое клиентского .conf файла для конкретного peer-а."""
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
            "AllowedIPs = 0.0.0.0/0, ::/0",
            f"PersistentKeepalive = {config.WG_KEEPALIVE_SECONDS}",
            "",
        ]
    )


def allocate_next_ip(subnet: str, used_ips: set[str]) -> str:
    """
    Находит следующий свободный IP в подсети (кроме .0/сеть, .1/сервер
    и .255/broadcast для /24). Подсеть должна быть вида '10.66.0.0/24'.
    """
    network_part = subnet.split("/")[0]
    octets = network_part.split(".")
    if len(octets) != 4:
        raise ValueError(f"Некорректная подсеть: {subnet!r}")
    base = ".".join(octets[:3])

    for host_octet in range(2, 255):  # .1 зарезервирован под сервер
        candidate = f"{base}.{host_octet}"
        if candidate not in used_ips:
            return candidate
    raise RuntimeError(f"В подсети {subnet} закончились свободные IP-адреса")
