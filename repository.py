"""
Repository Pattern: единственная точка доступа к таблице proxies.
Никакой бизнес-логики — только CRUD.
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone

import config
from database import get_connection
from models import Proxy

logger = logging.getLogger(__name__)


class ProxyAlreadyExistsError(RuntimeError):
    """Прокси с таким именем контейнера уже существует в базе."""


class ProxyNotFoundError(RuntimeError):
    """Прокси с указанным идентификатором не найден."""


def _row_to_proxy(row: sqlite3.Row) -> Proxy:
    return Proxy(
        id=row["id"],
        container_name=row["container_name"],
        ip=row["ip"],
        port=row["port"],
        secret=row["secret"],
        tg_link=row["tg_link"],
        https_link=row["https_link"],
        qr_filename=row["qr_filename"],
        status=row["status"],
        created_at=row["created_at"],
    )


class ProxyRepository:
    """Инкапсулирует все SQL-запросы к таблице proxies."""

    def create(
        self,
        *,
        container_name: str,
        ip: str,
        port: int,
        secret: str,
        tg_link: str,
        https_link: str,
        qr_filename: str,
        status: str,
    ) -> Proxy:
        created_at = datetime.now(timezone.utc).isoformat()
        try:
            with get_connection() as connection:
                cursor = connection.execute(
                    f"""
                    INSERT INTO {config.PROXIES_TABLE_NAME}
                        (container_name, ip, port, secret, tg_link,
                         https_link, qr_filename, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        container_name,
                        ip,
                        port,
                        secret,
                        tg_link,
                        https_link,
                        qr_filename,
                        status,
                        created_at,
                    ),
                )
                new_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise ProxyAlreadyExistsError(
                f"Прокси с именем контейнера '{container_name}' уже существует"
            ) from exc

        return Proxy(
            id=new_id,
            container_name=container_name,
            ip=ip,
            port=port,
            secret=secret,
            tg_link=tg_link,
            https_link=https_link,
            qr_filename=qr_filename,
            status=status,
            created_at=created_at,
        )

    def get_all(self) -> list[Proxy]:
        with get_connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM {config.PROXIES_TABLE_NAME} ORDER BY id DESC"
            ).fetchall()
        return [_row_to_proxy(row) for row in rows]

    def get_by_id(self, proxy_id: int) -> Proxy:
        with get_connection() as connection:
            row = connection.execute(
                f"SELECT * FROM {config.PROXIES_TABLE_NAME} WHERE id = ?",
                (proxy_id,),
            ).fetchone()
        if row is None:
            raise ProxyNotFoundError(f"Прокси с id={proxy_id} не найден")
        return _row_to_proxy(row)

    def exists_by_container_name(self, container_name: str) -> bool:
        with get_connection() as connection:
            row = connection.execute(
                f"SELECT 1 FROM {config.PROXIES_TABLE_NAME} WHERE container_name = ?",
                (container_name,),
            ).fetchone()
        return row is not None

    def update_status(self, proxy_id: int, status: str) -> None:
        with get_connection() as connection:
            cursor = connection.execute(
                f"UPDATE {config.PROXIES_TABLE_NAME} SET status = ? WHERE id = ?",
                (status, proxy_id),
            )
        if cursor.rowcount == 0:
            raise ProxyNotFoundError(f"Прокси с id={proxy_id} не найден")

    def delete(self, proxy_id: int) -> Proxy:
        proxy = self.get_by_id(proxy_id)
        with get_connection() as connection:
            connection.execute(
                f"DELETE FROM {config.PROXIES_TABLE_NAME} WHERE id = ?",
                (proxy_id,),
            )
        return proxy
