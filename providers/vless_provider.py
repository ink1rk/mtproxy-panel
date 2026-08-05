"""Адаптер VLESS+REALITY поверх vpn_service.XrayService."""
from __future__ import annotations

import config
from models import ProviderClient, VlessClient
from providers.base import ProviderError, VpnProvider
from vpn_service import VpnServiceError, XrayService


def _to_client(client: VlessClient) -> ProviderClient:
    return ProviderClient(
        id=str(client.id),
        name=client.name,
        created_at=client.created_at,
        config_text=client.vless_link,
        qr_filename=client.qr_filename,
        primary_label="UUID",
        primary_value=client.client_uuid[:8],
        secondary_label="Ссылка",
        secondary_value=client.vless_link,
    )


class VlessProvider(VpnProvider):
    key = "vless"
    display_name = "VLESS + REALITY"
    icon = "bi-diagram-3"

    def __init__(self) -> None:
        try:
            self._service = XrayService()
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def is_configured(self) -> bool:
        return self._service.get_server_config() is not None

    def ensure_ready(self) -> ProviderClient | None:
        try:
            client = self._service.ensure_ready()
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc
        return _to_client(client) if client else None

    def status(self) -> str:
        return self._service.get_status()

    def endpoint(self) -> str:
        cfg = self._service.get_server_config()
        return f"{cfg.server_names}:{cfg.listen_port}" if cfg else ""

    def list_clients(self) -> list[ProviderClient]:
        return [_to_client(c) for c in self._service.list_clients()]

    def add_client(self, name: str) -> ProviderClient:
        try:
            return _to_client(self._service.add_client(name))
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def delete_client(self, client_id: str) -> None:
        try:
            self._service.delete_client(int(client_id))
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def restart(self) -> None:
        try:
            self._service.restart_server()
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def reset(self) -> None:
        self._service.reset_server()

    def setup(self, *, listen_port: str, dest: str, server_name: str, **_: str) -> None:
        cleaned_port = listen_port.strip()
        if not cleaned_port.isdigit():
            raise ProviderError("Укажите корректный номер порта")
        if not dest.strip() or ":" not in dest:
            raise ProviderError("Укажите dest в формате домен:порт, например www.microsoft.com:443")
        try:
            self._service.setup_server(
                listen_port=int(cleaned_port), dest=dest.strip(), server_name=server_name.strip(),
            )
        except VpnServiceError as exc:
            raise ProviderError(str(exc)) from exc

    def setup_fields(self) -> list[tuple[str, str, str, str]]:
        return [
            ("listen_port", "TCP-порт сервера", str(config.XRAY_DEFAULT_PORT), "number"),
            ("dest", "Dest (сайт для маскировки, домен:порт)", config.XRAY_DEFAULT_DEST, "text"),
            ("server_name", "Server Name (SNI)", config.XRAY_DEFAULT_SERVER_NAMES[0], "text"),
        ]
