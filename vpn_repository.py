"""
Repository Pattern для VPN-подсистем: WireGuard и Xray/VLESS.
Только CRUD, никакой бизнес-логики (генерация ключей, systemd/nftables
и т.д. находятся в vpn_service.py / wireguard_manager.py / xray_manager.py).
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone

import config
from database import get_connection
from models import VlessClient, WireGuardPeer, WireGuardServerConfig, XrayServerConfig

logger = logging.getLogger(__name__)


class AlreadyExistsError(RuntimeError):
    """Запись с таким уникальным именем уже существует."""


class NotFoundError(RuntimeError):
    """Запись не найдена."""


# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------
def _row_to_wg_server_config(row: sqlite3.Row) -> WireGuardServerConfig:
    return WireGuardServerConfig(
        server_private_key=row["server_private_key"],
        server_public_key=row["server_public_key"],
        listen_port=row["listen_port"],
        subnet=row["subnet"],
        endpoint_ip=row["endpoint_ip"],
        dns=row["dns"],
        created_at=row["created_at"],
    )


def _row_to_wg_peer(row: sqlite3.Row) -> WireGuardPeer:
    return WireGuardPeer(
        id=row["id"],
        name=row["name"],
        private_key=row["private_key"],
        public_key=row["public_key"],
        allocated_ip=row["allocated_ip"],
        config_text=row["config_text"],
        qr_filename=row["qr_filename"],
        created_at=row["created_at"],
    )


class WireGuardRepository:
    """CRUD для серверного конфига WireGuard (singleton-строка) и peer-ов."""

    def get_server_config(self) -> WireGuardServerConfig | None:
        with get_connection() as connection:
            row = connection.execute(
                f"SELECT * FROM {config.WG_SERVER_CONFIG_TABLE_NAME} WHERE id = 1"
            ).fetchone()
        return _row_to_wg_server_config(row) if row else None

    def save_server_config(
        self,
        *,
        server_private_key: str,
        server_public_key: str,
        listen_port: int,
        subnet: str,
        endpoint_ip: str,
        dns: str,
    ) -> WireGuardServerConfig:
        created_at = datetime.now(timezone.utc).isoformat()
        with get_connection() as connection:
            connection.execute(
                f"""
                INSERT INTO {config.WG_SERVER_CONFIG_TABLE_NAME}
                    (id, server_private_key, server_public_key, listen_port,
                     subnet, endpoint_ip, dns, created_at)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    server_private_key = excluded.server_private_key,
                    server_public_key = excluded.server_public_key,
                    listen_port = excluded.listen_port,
                    subnet = excluded.subnet,
                    endpoint_ip = excluded.endpoint_ip,
                    dns = excluded.dns
                """,
                (server_private_key, server_public_key, listen_port, subnet, endpoint_ip, dns, created_at),
            )
        result = self.get_server_config()
        assert result is not None
        return result

    def get_all_peers(self) -> list[WireGuardPeer]:
        with get_connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM {config.WG_PEERS_TABLE_NAME} ORDER BY id DESC"
            ).fetchall()
        return [_row_to_wg_peer(row) for row in rows]

    def get_peer_by_id(self, peer_id: int) -> WireGuardPeer:
        with get_connection() as connection:
            row = connection.execute(
                f"SELECT * FROM {config.WG_PEERS_TABLE_NAME} WHERE id = ?", (peer_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError(f"WireGuard peer с id={peer_id} не найден")
        return _row_to_wg_peer(row)

    def get_used_ips(self) -> set[str]:
        with get_connection() as connection:
            rows = connection.execute(f"SELECT allocated_ip FROM {config.WG_PEERS_TABLE_NAME}").fetchall()
        return {row["allocated_ip"] for row in rows}

    def create_peer(
        self,
        *,
        name: str,
        private_key: str,
        public_key: str,
        allocated_ip: str,
        config_text: str,
        qr_filename: str,
    ) -> WireGuardPeer:
        created_at = datetime.now(timezone.utc).isoformat()
        try:
            with get_connection() as connection:
                cursor = connection.execute(
                    f"""
                    INSERT INTO {config.WG_PEERS_TABLE_NAME}
                        (name, private_key, public_key, allocated_ip, config_text, qr_filename, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (name, private_key, public_key, allocated_ip, config_text, qr_filename, created_at),
                )
                new_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise AlreadyExistsError(f"Peer с именем '{name}' уже существует") from exc

        return WireGuardPeer(
            id=new_id, name=name, private_key=private_key, public_key=public_key,
            allocated_ip=allocated_ip, config_text=config_text, qr_filename=qr_filename,
            created_at=created_at,
        )

    def update_peer_config(self, peer_id: int, *, config_text: str) -> None:
        with get_connection() as connection:
            connection.execute(
                f"UPDATE {config.WG_PEERS_TABLE_NAME} SET config_text = ? WHERE id = ?",
                (config_text, peer_id),
            )

    def delete_peer(self, peer_id: int) -> WireGuardPeer:
        peer = self.get_peer_by_id(peer_id)
        with get_connection() as connection:
            connection.execute(f"DELETE FROM {config.WG_PEERS_TABLE_NAME} WHERE id = ?", (peer_id,))
        return peer

    def delete_all_peers(self) -> None:
        with get_connection() as connection:
            connection.execute(f"DELETE FROM {config.WG_PEERS_TABLE_NAME}")

    def delete_server_config(self) -> None:
        with get_connection() as connection:
            connection.execute(f"DELETE FROM {config.WG_SERVER_CONFIG_TABLE_NAME} WHERE id = 1")


# ---------------------------------------------------------------------------
# Xray / VLESS
# ---------------------------------------------------------------------------
def _row_to_xray_server_config(row: sqlite3.Row) -> XrayServerConfig:
    return XrayServerConfig(
        listen_port=row["listen_port"],
        dest=row["dest"],
        server_names=row["server_names"],
        private_key=row["private_key"],
        public_key=row["public_key"],
        short_id=row["short_id"],
        created_at=row["created_at"],
    )


def _row_to_vless_client(row: sqlite3.Row) -> VlessClient:
    return VlessClient(
        id=row["id"],
        name=row["name"],
        client_uuid=row["client_uuid"],
        vless_link=row["vless_link"],
        qr_filename=row["qr_filename"],
        created_at=row["created_at"],
    )


class XrayRepository:
    """CRUD для серверного конфига Xray (singleton-строка) и VLESS-клиентов."""

    def get_server_config(self) -> XrayServerConfig | None:
        with get_connection() as connection:
            row = connection.execute(
                f"SELECT * FROM {config.XRAY_SERVER_CONFIG_TABLE_NAME} WHERE id = 1"
            ).fetchone()
        return _row_to_xray_server_config(row) if row else None

    def save_server_config(
        self,
        *,
        listen_port: int,
        dest: str,
        server_names: str,
        private_key: str,
        public_key: str,
        short_id: str,
    ) -> XrayServerConfig:
        created_at = datetime.now(timezone.utc).isoformat()
        with get_connection() as connection:
            connection.execute(
                f"""
                INSERT INTO {config.XRAY_SERVER_CONFIG_TABLE_NAME}
                    (id, listen_port, dest, server_names, private_key, public_key, short_id, created_at)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    listen_port = excluded.listen_port,
                    dest = excluded.dest,
                    server_names = excluded.server_names,
                    private_key = excluded.private_key,
                    public_key = excluded.public_key,
                    short_id = excluded.short_id
                """,
                (listen_port, dest, server_names, private_key, public_key, short_id, created_at),
            )
        result = self.get_server_config()
        assert result is not None
        return result

    def get_all_clients(self) -> list[VlessClient]:
        with get_connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM {config.VLESS_CLIENTS_TABLE_NAME} ORDER BY id DESC"
            ).fetchall()
        return [_row_to_vless_client(row) for row in rows]

    def get_client_by_id(self, client_id: int) -> VlessClient:
        with get_connection() as connection:
            row = connection.execute(
                f"SELECT * FROM {config.VLESS_CLIENTS_TABLE_NAME} WHERE id = ?", (client_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError(f"VLESS-клиент с id={client_id} не найден")
        return _row_to_vless_client(row)

    def create_client(
        self, *, name: str, client_uuid: str, vless_link: str, qr_filename: str
    ) -> VlessClient:
        created_at = datetime.now(timezone.utc).isoformat()
        try:
            with get_connection() as connection:
                cursor = connection.execute(
                    f"""
                    INSERT INTO {config.VLESS_CLIENTS_TABLE_NAME}
                        (name, client_uuid, vless_link, qr_filename, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (name, client_uuid, vless_link, qr_filename, created_at),
                )
                new_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise AlreadyExistsError(f"VLESS-клиент с именем '{name}' уже существует") from exc

        return VlessClient(
            id=new_id, name=name, client_uuid=client_uuid,
            vless_link=vless_link, qr_filename=qr_filename, created_at=created_at,
        )

    def update_client_link(self, client_id: int, *, vless_link: str) -> None:
        with get_connection() as connection:
            connection.execute(
                f"UPDATE {config.VLESS_CLIENTS_TABLE_NAME} SET vless_link = ? WHERE id = ?",
                (vless_link, client_id),
            )

    def delete_client(self, client_id: int) -> VlessClient:
        client = self.get_client_by_id(client_id)
        with get_connection() as connection:
            connection.execute(f"DELETE FROM {config.VLESS_CLIENTS_TABLE_NAME} WHERE id = ?", (client_id,))
        return client

    def delete_all_clients(self) -> None:
        with get_connection() as connection:
            connection.execute(f"DELETE FROM {config.VLESS_CLIENTS_TABLE_NAME}")

    def delete_server_config(self) -> None:
        with get_connection() as connection:
            connection.execute(f"DELETE FROM {config.XRAY_SERVER_CONFIG_TABLE_NAME} WHERE id = 1")
