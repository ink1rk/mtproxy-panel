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
    columns_sql = ", ".join(
        f"{name} {definition}"
        for name, definition in config.EXPECTED_PROXIES_COLUMNS.items()
    )
    connection.execute(
        f"CREATE TABLE IF NOT EXISTS {config.PROXIES_TABLE_NAME} ({columns_sql})"
    )


def _migrate_missing_columns(connection: sqlite3.Connection) -> None:
    """
    Сравнивает текущую схему таблицы с ожидаемой и добавляет
    отсутствующие столбцы через ALTER TABLE ADD COLUMN.
    """
    existing_columns = {
        row["name"]
        for row in connection.execute(
            f"PRAGMA table_info({config.PROXIES_TABLE_NAME})"
        ).fetchall()
    }

    for column_name, definition in config.EXPECTED_PROXIES_COLUMNS.items():
        if column_name in existing_columns:
            continue
        if "PRIMARY KEY" in definition.upper():
            # PRIMARY KEY нельзя добавить через ALTER TABLE — эта колонка
            # создаётся только при первичном CREATE TABLE.
            continue
        logger.info("Миграция: добавляю отсутствующую колонку '%s'", column_name)
        safe_definition = definition.replace("UNIQUE", "").replace("NOT NULL", "")
        connection.execute(
            f"ALTER TABLE {config.PROXIES_TABLE_NAME} "
            f"ADD COLUMN {column_name} {safe_definition}"
        )


def init_db() -> None:
    """
    Инициализирует базу данных при старте приложения:
    создаёт таблицу, если её нет, и выполняет миграцию отсутствующих колонок.
    """
    with get_connection() as connection:
        _create_table_if_missing(connection)
        _migrate_missing_columns(connection)
    logger.info("База данных инициализирована: %s", config.DATABASE_PATH)
