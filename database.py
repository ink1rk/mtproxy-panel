"""
Слой работы с SQLite: контекстный менеджер соединения,
создание таблиц и автоматическая миграция схемы.
"""
from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

import config

logger = logging.getLogger(__name__)


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """
    Контекстный менеджер, выдающий соединение с SQLite.
    Автоматически коммитит при успехе и откатывает при исключении.
    """
    connection = sqlite3.connect(
        config.DATABASE_PATH,
        timeout=30.0,
        isolation_level=None,  # autocommit off, управляем транзакциями вручную
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    try:
        connection.execute("BEGIN")
        yield connection
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def _create_table_if_missing(connection: sqlite3.Connection) -> None:
    proxies_columns_sql = ", ".join(
        f"{name} {definition}"
        for name, definition in config.EXPECTED_PROXIES_COLUMNS.items()
    )
    connection.execute(
        f"CREATE TABLE IF NOT EXISTS {config.PROXIES_TABLE_NAME} ({proxies_columns_sql})"
    )

    admin_columns_sql = ", ".join(
        f"{name} {definition}"
        for name, definition in config.EXPECTED_ADMIN_USERS_COLUMNS.items()
    )
    connection.execute(
        f"CREATE TABLE IF NOT EXISTS {config.ADMIN_USERS_TABLE_NAME} ({admin_columns_sql})"
    )


def _migrate_table_columns(
    connection: sqlite3.Connection,
    table_name: str,
    expected_columns: dict[str, str],
) -> None:
    """
    Сравнивает текущую схему указанной таблицы с ожидаемой и добавляет
    отсутствующие столбцы через ALTER TABLE ADD COLUMN.
    """
    existing_columns = {
        row["name"] for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    }

    for column_name, definition in expected_columns.items():
        if column_name in existing_columns:
            continue
        if "PRIMARY KEY" in definition.upper():
            # PRIMARY KEY нельзя добавить через ALTER TABLE — эта колонка
            # создаётся только при первичном CREATE TABLE.
            continue
        logger.info("Миграция: добавляю отсутствующую колонку '%s.%s'", table_name, column_name)
        safe_definition = definition.replace("UNIQUE", "").replace("NOT NULL", "")
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {safe_definition}")


def init_db() -> None:
    """
    Инициализирует базу данных при старте приложения:
    создаёт таблицы, если их нет, и выполняет миграцию отсутствующих колонок.
    """
    with get_connection() as connection:
        _create_table_if_missing(connection)
        _migrate_table_columns(connection, config.PROXIES_TABLE_NAME, config.EXPECTED_PROXIES_COLUMNS)
        _migrate_table_columns(
            connection, config.ADMIN_USERS_TABLE_NAME, config.EXPECTED_ADMIN_USERS_COLUMNS
        )
    logger.info("База данных инициализирована: %s", config.DATABASE_PATH)
