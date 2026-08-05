"""Адаптер WireGuard поверх vpn_service.WireGuardService."""
from __future__ import annotations

import config
from models import ProviderClient, WireGuardPeer
from providers.base import ProviderError, VpnProvider
from vpn_service import VpnServiceError, WireGuardService


def _to_client(
    peer: WireGuardPeer, *, connection_label: str = "", traffic_label: str = "",
) -> ProviderClient:
    return ProviderClient(
        id=str(peer.id),
        name=peer.name,
        created_at=peer.created_at,
        config_text=peer.config_text,
        qr_filename=peer.qr_filename,
        primary_label="VPN-адрес",
        primary_value=peer.allocated_ip,
        secondary_label="Public Key",
        secondary_value=peer.public_key,
        connection_label=connection_label,
        traffic_label=traffic_label,
    )


class WireGuardProvider(VpnProvider):
    key = "wireguard"
    display_name = "WireGuard"
    icon = "bi-hdd-network"

    def __init__(self) -> None:
        try:
            self._service = WireGuardService()
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def is_configured(self) -> bool:
        return self._service.get_server_config() is not None

    def ensure_ready(self) -> ProviderClient | None:
        try:
            peer = self._service.ensure_ready()
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc
        return _to_client(peer) if peer else None

    def status(self) -> str:
        return self._service.get_status()

    def endpoint(self) -> str:
        cfg = self._service.get_server_config()
        return f"{cfg.endpoint_ip}:{cfg.listen_port}" if cfg else ""

    def list_clients(self) -> list[ProviderClient]:
        connection_labels = self._service.get_peer_connection_labels()
        traffic_labels = self._service.get_peer_traffic_labels()
        return [
            _to_client(
                peer,
                connection_label=connection_labels.get(peer.id, ""),
                traffic_label=traffic_labels.get(peer.id, ""),
            )
            for peer in self._service.list_peers()
        ]

    def add_client(self, name: str) -> ProviderClient:
        try:
            return _to_client(self._service.add_peer(name))
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def delete_client(self, client_id: str) -> None:
        try:
            self._service.delete_peer(int(client_id))
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def restart(self) -> None:
        try:
            self._service.restart_server()
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def reset(self) -> None:
        self._service.reset_server()

    def setup(self, *, listen_port: str, subnet: str, dns: str, **_: str) -> None:
        cleaned_port = listen_port.strip()
        if not cleaned_port.isdigit():
            raise ProviderError("Укажите корректный номер порта")
        try:
            self._service.setup_server(
                listen_port=int(cleaned_port), subnet=subnet.strip(), dns=dns.strip(),
            )
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def setup_fields(self) -> list[tuple[str, str, str, str]]:
        return [
            ("listen_port", "UDP-порт сервера", str(config.WG_DEFAULT_PORT), "number"),
            ("subnet", "Внутренняя подсеть VPN", config.WG_DEFAULT_SUBNET, "text"),
            ("dns", "DNS для клиентов", config.WG_DEFAULT_DNS, "text"),
        ]

    def diagnostics(self) -> dict | None:
        return self._service.diagnostics()
