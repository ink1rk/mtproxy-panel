"""
Аутентификация: хранение администратора, хеширование паролей (PBKDF2 + соль,
стандартная библиотека, без внешних зависимостей вроде bcrypt), проверка
логина/пароля и защита роутов через сессионную куку.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import sqlite3
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import RedirectResponse

import config
from database import get_connection
from models import AdminUser

logger = logging.getLogger(__name__)

SESSION_USER_KEY = "admin_username"


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """
    Хеширует пароль через PBKDF2-HMAC-SHA256 с криптостойкой солью.
    Возвращает (password_hash_hex, salt_hex).
    """
    if salt is None:
        salt = secrets.token_hex(config.PBKDF2_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        config.PBKDF2_ALGORITHM,
        password.encode("utf-8"),
        bytes.fromhex(salt),
        config.PBKDF2_ITERATIONS,
    )
    return derived.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Сравнивает пароль с хешем через сравнение с постоянным временем."""
    candidate_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, password_hash)


def generate_strong_password() -> str:
    """Генерирует криптостойкий пароль для первичной учётной записи администратора."""
    return secrets.token_urlsafe(config.GENERATED_PASSWORD_LENGTH_BYTES)


class AdminUserRepository:
    """Repository Pattern для таблицы admin_users."""

    def get_by_username(self, username: str) -> AdminUser | None:
        with get_connection() as connection:
            row = connection.execute(
                f"SELECT * FROM {config.ADMIN_USERS_TABLE_NAME} WHERE username = ?",
                (username,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_user(row)

    def count(self) -> int:
        with get_connection() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) AS cnt FROM {config.ADMIN_USERS_TABLE_NAME}"
            ).fetchone()
        return int(row["cnt"])

    def create(self, username: str, password: str) -> AdminUser:
        password_hash, salt = hash_password(password)
        created_at = datetime.now(timezone.utc).isoformat()
        try:
            with get_connection() as connection:
                cursor = connection.execute(
                    f"""
                    INSERT INTO {config.ADMIN_USERS_TABLE_NAME}
                        (username, password_hash, password_salt, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, password_hash, salt, created_at),
                )
                new_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Пользователь '{username}' уже существует") from exc

        return AdminUser(
            id=new_id,
            username=username,
            password_hash=password_hash,
            password_salt=salt,
            created_at=created_at,
        )

    def update_password(self, username: str, new_password: str) -> None:
        password_hash, salt = hash_password(new_password)
        with get_connection() as connection:
            cursor = connection.execute(
                f"""
                UPDATE {config.ADMIN_USERS_TABLE_NAME}
                SET password_hash = ?, password_salt = ?
                WHERE username = ?
                """,
                (password_hash, salt, username),
            )
        if cursor.rowcount == 0:
            raise ValueError(f"Пользователь '{username}' не найден")

    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> AdminUser:
        return AdminUser(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            password_salt=row["password_salt"],
            created_at=row["created_at"],
        )


def ensure_initial_admin_exists() -> str | None:
    """
    Если ни одного администратора ещё нет — создаёт первую учётную запись
    со случайным паролем, сохраняет маркер и возвращает пароль в открытом
    виде (только для однократного вывода в лог при первом запуске).
    Если администратор уже есть — возвращает None.
    """
    repository = AdminUserRepository()
    if repository.count() > 0:
        return None

    password = generate_strong_password()
    repository.create(config.DEFAULT_ADMIN_USERNAME, password)
    logger.warning(
        "Создана первая учётная запись администратора: логин='%s'. "
        "Пароль показан один раз ниже — сохраните его.",
        config.DEFAULT_ADMIN_USERNAME,
    )
    return password


def authenticate(username: str, password: str) -> bool:
    """Проверяет логин и пароль. Не раскрывает, что именно неверно."""
    repository = AdminUserRepository()
    user = repository.get_by_username(username)
    if user is None:
        # Тратим время на фиктивное хеширование, чтобы не давать оракул
        # по времени ответа для перебора существующих логинов.
        hash_password(password)
        return False
    return verify_password(password, user.password_hash, user.password_salt)


def is_authenticated(request: Request) -> bool:
    """Проверяет, есть ли в текущей сессии авторизованный пользователь."""
    return bool(request.session.get(SESSION_USER_KEY))


def log_in(request: Request, username: str) -> None:
    """Помечает сессию как авторизованную для указанного пользователя."""
    request.session[SESSION_USER_KEY] = username


def log_out(request: Request) -> None:
    """Очищает сессию."""
    request.session.clear()


def require_login_redirect(request: Request) -> RedirectResponse | None:
    """
    Возвращает RedirectResponse на /login, если пользователь не авторизован,
    иначе None. Роуты вызывают эту функцию первой строкой.
    """
    if is_authenticated(request):
        return None
    return RedirectResponse(url="/login", status_code=303)


def load_or_create_session_secret() -> str:
    """Загружает постоянный секретный ключ для подписи сессионных кук,
    либо генерирует новый при первом запуске и сохраняет его на диск."""
    if config.SESSION_SECRET_PATH.exists():
        secret = config.SESSION_SECRET_PATH.read_text(encoding="utf-8").strip()
        if secret:
            return secret

    secret = secrets.token_hex(32)
    config.SESSION_SECRET_PATH.write_text(secret, encoding="utf-8")
    config.SESSION_SECRET_PATH.chmod(0o600)
    return secret
