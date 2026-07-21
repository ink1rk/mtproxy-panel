"""
Pydantic v2 схемы для API-слоя.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ProxyOut(BaseModel):
    """Схема ответа с данными одного прокси."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    container_name: str
    ip: str
    port: int = Field(ge=1, le=65535)
    secret: str
    tg_link: str
    https_link: str
    qr_url: str
    status: str
    created_at: str


class ProxyCreateResponse(BaseModel):
    """Ответ на создание прокси."""

    model_config = ConfigDict(from_attributes=True)

    proxy: ProxyOut
    message: str = "Прокси успешно создан"


class ErrorResponse(BaseModel):
    """Единый формат ошибки."""

    detail: str
