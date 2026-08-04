"""
Криптографические примитивы для WireGuard и Xray REALITY.

И WireGuard, и Xray REALITY используют одну и ту же эллиптическую кривую —
Curve25519 (X25519) — но кодируют ключи в base64 по-разному:

- WireGuard: стандартный base64 с padding ('+', '/', '=').
- Xray REALITY: base64 URL-safe БЕЗ padding ('-', '_', без '=').

Ключи генерируются напрямую средствами библиотеки `cryptography`, без
вызова внешних бинарников (`wg genkey`, `xray x25519`), поэтому не требуют
их наличия в системе.
"""
from __future__ import annotations

import base64
import secrets
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

import config


def _generate_x25519_raw_keypair() -> tuple[bytes, bytes]:
    """Генерирует пару X25519 ключей, возвращает (private_raw, public_raw) по 32 байта."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_raw, public_raw


def generate_wireguard_keypair() -> tuple[str, str]:
    """
    Генерирует пару ключей WireGuard.
    Возвращает (private_key_base64, public_key_base64) — стандартный
    base64 с padding, как того ожидает формат конфигов wg-quick.
    """
    private_raw, public_raw = _generate_x25519_raw_keypair()
    private_key = base64.b64encode(private_raw).decode("ascii")
    public_key = base64.b64encode(public_raw).decode("ascii")
    return private_key, public_key


def generate_wireguard_preshared_key() -> str:
    """PresharedKey как у `wg genpsk` / wg-easy (32 random bytes, base64)."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def generate_reality_keypair() -> tuple[str, str]:
    """
    Генерирует пару ключей для Xray REALITY.
    Возвращает (private_key, public_key) — base64 URL-safe БЕЗ padding,
    как того ожидает формат вывода 'xray x25519' и realitySettings.
    """
    private_raw, public_raw = _generate_x25519_raw_keypair()
    private_key = base64.urlsafe_b64encode(private_raw).rstrip(b"=").decode("ascii")
    public_key = base64.urlsafe_b64encode(public_raw).rstrip(b"=").decode("ascii")
    return private_key, public_key


def generate_reality_short_id() -> str:
    """Генерирует shortId для REALITY — hex-строка (Xray принимает 0-16 hex символов)."""
    return secrets.token_hex(config.XRAY_SHORT_ID_BYTES)


def generate_client_uuid() -> str:
    """Генерирует UUID для VLESS-клиента (Xray требует валидный UUID или произвольную строку 1-30 символов)."""
    return str(uuid.uuid4())
