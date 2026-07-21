"""
HTTP-роуты. Никакой бизнес-логики и никакого прямого обращения
к Docker/SQLite — только вызовы ProxyService.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import config
from service import ProxyService, ProxyServiceError
from utils import escape_html

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory=str(config.TEMPLATES_DIR))


def _try_get_service() -> tuple[ProxyService | None, str | None]:
    """
    Пытается создать сервис. Если Docker недоступен (или иная ошибка
    инициализации), возвращает (None, текст_ошибки) вместо исключения,
    чтобы роуты могли корректно отрендерить страницу с ошибкой.
    """
    try:
        return ProxyService(), None
    except ProxyServiceError as exc:
        logger.error("Не удалось инициализировать ProxyService: %s", exc)
        return None, str(exc)


@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Главная страница со списком всех прокси."""
    error_message: str | None = request.query_params.get("error")
    proxies = []

    service, init_error = _try_get_service()
    if init_error is not None:
        error_message = init_error
    else:
        assert service is not None
        try:
            proxies = service.list_proxies()
        except ProxyServiceError as exc:
            error_message = str(exc)
            logger.error("Ошибка получения списка прокси: %s", exc)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "proxies": proxies,
            "error_message": error_message,
        },
    )


@router.post("/proxies", response_class=RedirectResponse)
async def create_proxy(request: Request) -> RedirectResponse:
    """Создаёт новый MTProxy и возвращает пользователя на главную страницу."""
    service, init_error = _try_get_service()
    if init_error is not None:
        return RedirectResponse(url=f"/?error={escape_html(init_error)}", status_code=303)

    assert service is not None
    try:
        service.create_proxy()
    except ProxyServiceError as exc:
        logger.error("Ошибка создания прокси: %s", exc)
        return RedirectResponse(url=f"/?error={escape_html(str(exc))}", status_code=303)
    return RedirectResponse(url="/", status_code=303)


@router.post("/proxies/{proxy_id}/delete", response_class=RedirectResponse)
async def delete_proxy(request: Request, proxy_id: int) -> RedirectResponse:
    """Удаляет MTProxy по идентификатору и возвращает на главную страницу."""
    service, init_error = _try_get_service()
    if init_error is not None:
        return RedirectResponse(url=f"/?error={escape_html(init_error)}", status_code=303)

    assert service is not None
    try:
        service.delete_proxy(proxy_id)
    except ProxyServiceError as exc:
        logger.error("Ошибка удаления прокси id=%d: %s", proxy_id, exc)
        return RedirectResponse(url=f"/?error={escape_html(str(exc))}", status_code=303)
    return RedirectResponse(url="/", status_code=303)
