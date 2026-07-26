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

# Реестр всех таблиц приложения: (имя_таблицы, ожидаемые_колонки).
# Добавление новой таблицы = добавление одной строки сюда; создание и
# миграция схемы происходят автоматически для всех таблиц из реестра.
_TABLE_REGISTRY: tuple[tuple[str, dict[str, str]], ...] = (
    (config.PROXIES_TABLE_NAME, config.EXPECTED_PROXIES_COLUMNS),
    (config.ADMIN_USERS_TABLE_NAME, config.EXPECTED_ADMIN_USERS_COLUMNS),
    (config.WG_SERVER_CONFIG_TABLE_NAME, config.EXPECTED_WG_SERVER_CONFIG_COLUMNS),
    (config.WG_PEERS_TABLE_NAME, config.EXPECTED_WG_PEERS_COLUMNS),
    (config.XRAY_SERVER_CONFIG_TABLE_NAME, config.EXPECTED_XRAY_SERVER_CONFIG_COLUMNS),
    (config.VLESS_CLIENTS_TABLE_NAME, config.EXPECTED_VLESS_CLIENTS_COLUMNS),
)


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


def _create_table_if_missing(
    connection: sqlite3.Connection, table_name: str, expected_columns: dict[str, str]
) -> None:
    columns_sql = ", ".join(f"{name} {definition}" for name, definition in expected_columns.items())
    connection.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({columns_sql})")


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
        # CHECK-констрейнты (например 'CHECK (id = 1)') относятся к таблице
        # целиком и не могут быть добавлены через ALTER TABLE ADD COLUMN —
        # такие определения тоже безопасно урезаем при миграции колонки.
        if "CHECK" in safe_definition.upper():
            safe_definition = safe_definition.split("CHECK")[0].strip()
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {safe_definition}")


def init_db() -> None:
    """
    Инициализирует базу данных при старте приложения:
    создаёт все таблицы из реестра, если их нет, и выполняет миграцию
    отсутствующих колонок в каждой из них.
    """
    with get_connection() as connection:
        for table_name, expected_columns in _TABLE_REGISTRY:
            _create_table_if_missing(connection, table_name, expected_columns)
        for table_name, expected_columns in _TABLE_REGISTRY:
            _migrate_table_columns(connection, table_name, expected_columns)
    logger.info("База данных инициализирована: %s", config.DATABASE_PATH)
