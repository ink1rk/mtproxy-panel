"""
Абстрактный интерфейс VPN/прокси-провайдера.

Любой протокол (WireGuard/VLESS/MTProxy/...) реализует ЭТИ методы и ничего
не знает о них снаружи — routes.py/шаблоны работают с VpnProvider и
ProviderClient, не зная, что стоит за конкретным ключом ("wireguard"
или "vless"). Это устраняет необходимость дублировать HTTP-роуты,
Jinja-шаблоны и boilerplate инициализации сервиса под каждый новый
протокол (см. providers/registry.py и templates/provider.html).

Реализации (providers/wireguard_provider.py и т.д.) — тонкие адаптеры
над существующими *_service.py: вся протокол-специфичная логика
(systemd/iptables/Docker/Xray-конфиги) остаётся в *_manager.py, сюда
не переносится ничего низкоуровневого.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from models import ProviderClient


class ProviderError(RuntimeError):
    """Единая ошибка провайдера, безопасная для показа пользователю."""


class VpnProvider(ABC):
    key: str
    display_name: str
    icon: str = "bi-shield-lock"

    @abstractmethod
    def is_configured(self) -> bool:
        """Настроен ли сервер (есть ли серверный конфиг в БД)."""

    @abstractmethod
    def ensure_ready(self) -> ProviderClient | None:
        """
        Автопровижининг без ручных шагов: если сервер не настроен —
        настроить с дефолтами; если клиентов нет — создать одного.
        Возвращает "основного" клиента для большого QR на странице,
        либо None (провайдер выключен окружением или ошибка).
        """

    @abstractmethod
    def status(self) -> str:
        """'running' | 'stopped' | 'missing' | 'degraded' | ..."""

    @abstractmethod
    def endpoint(self) -> str:
        """Строка вида host:port для отображения. Пусто, если не настроен."""

    @abstractmethod
    def list_clients(self) -> list[ProviderClient]: ...

    @abstractmethod
    def add_client(self, name: str) -> ProviderClient: ...

    @abstractmethod
    def delete_client(self, client_id: str) -> None: ...

    @abstractmethod
    def restart(self) -> None:
        """Переприменить конфигурацию/NAT без полного сброса."""

    @abstractmethod
    def reset(self) -> None:
        """Полный сброс: удалить сервер и всех клиентов."""

    def setup(self, **kwargs: Any) -> None:
        """
        Первичная настройка сервера с явными параметрами (порт и т.п.).
        Нужна не всем провайдерам (MTProxy настраивать нечего — каждый
        клиент самодостаточен), поэтому не абстрактный метод.
        """
        raise NotImplementedError(f"{self.key}: ручная настройка не требуется")

    def setup_fields(self) -> list[tuple[str, str, str, str]]:
        """
        Поля формы первичной настройки: (имя_поля, подпись, default, type).
        Пустой список — форма настройки не нужна (setup() не поддерживается
        или сервер настраивается только автоматически).
        """
        return []

    def diagnostics(self) -> dict | None:
        """
        Опциональная расширенная диагностика (routing checks + per-client
        verdict). None — у провайдера её нет / нечего показывать.
        """
        return None
