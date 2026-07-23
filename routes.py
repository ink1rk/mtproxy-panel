"""
HTTP-роуты. Никакой бизнес-логики и никакого прямого обращения
к Docker/SQLite — только вызовы ProxyService / auth.py.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import auth
import config
import utils
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


def _redirect_with_error(path: str, message: str) -> RedirectResponse:
    return RedirectResponse(url=f"{path}?error={escape_html(message)}", status_code=303)


# ---------------------------------------------------------------------------
# Аутентификация
# ---------------------------------------------------------------------------
@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    if auth.is_authenticated(request):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error_message": request.query_params.get("error")},
    )


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if auth.authenticate(username.strip(), password):
        auth.log_in(request, username.strip())
        return RedirectResponse(url="/", status_code=303)
    logger.warning("Неудачная попытка входа для логина '%s'", username.strip())
    return _redirect_with_error("/login", "Неверный логин или пароль")


@router.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    auth.log_out(request)
    return RedirectResponse(url="/login", status_code=303)


@router.post("/account/password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    username = request.session.get(auth.SESSION_USER_KEY)
    if not auth.authenticate(username, current_password):
        return _redirect_with_error("/", "Текущий пароль указан неверно")
    if new_password != confirm_password:
        return _redirect_with_error("/", "Новый пароль и подтверждение не совпадают")
    if len(new_password) < config.MIN_PASSWORD_LENGTH:
        return _redirect_with_error(
            "/", f"Новый пароль должен быть не короче {config.MIN_PASSWORD_LENGTH} символов"
        )

    auth.AdminUserRepository().update_password(username, new_password)
    logger.info("Пароль администратора '%s' изменён", username)
    return RedirectResponse(url="/?message=Пароль+успешно+изменён", status_code=303)


# ---------------------------------------------------------------------------
# Основные страницы (защищены авторизацией)
# ---------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Главная страница со списком всех прокси."""
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    error_message: str | None = request.query_params.get("error")
    info_message: str | None = request.query_params.get("message")
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

    running_count = sum(1 for p in proxies if p.status == "running")

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "proxies": proxies,
            "error_message": error_message,
            "info_message": info_message,
            "total_count": len(proxies),
            "running_count": running_count,
            "username": request.session.get(auth.SESSION_USER_KEY),
            "valid_secret_modes": config.VALID_SECRET_MODES,
            "default_tls_domain": config.DEFAULT_TLS_DOMAIN,
        },
    )


@router.get("/api/status")
async def api_status(request: Request) -> JSONResponse:
    """Лёгкий JSON-эндпоинт для живого обновления статусов без перезагрузки страницы."""
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return JSONResponse({"detail": "unauthorized"}, status_code=401)

    service, init_error = _try_get_service()
    if init_error is not None:
        return JSONResponse({"detail": init_error}, status_code=503)

    assert service is not None
    try:
        proxies = service.list_proxies()
    except ProxyServiceError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=503)

    return JSONResponse(
        {"proxies": [{"id": p.id, "status": p.status} for p in proxies]}
    )


@router.post("/proxies", response_class=RedirectResponse)
async def create_proxy(
    request: Request,
    manual_port: str = Form(""),
    secret_mode: str = Form(config.SECRET_MODE_CLASSIC),
    tls_domain: str = Form(""),
):
    """Создаёт новый MTProxy и возвращает пользователя на главную страницу."""
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    logger.info(
        "POST /proxies получены поля формы: manual_port=%r, secret_mode=%r, tls_domain=%r",
        manual_port, secret_mode, tls_domain,
    )

    desired_port: int | None = None
    cleaned_port = manual_port.strip()
    if cleaned_port:
        if not cleaned_port.isdigit():
            return _redirect_with_error("/", "Укажите корректный номер порта (только цифры)")
        desired_port = int(cleaned_port)

    cleaned_domain = tls_domain.strip() or None
    if secret_mode not in config.VALID_SECRET_MODES:
        return _redirect_with_error("/", "Неизвестный режим секрета")
    if secret_mode == config.SECRET_MODE_EE and not cleaned_domain:
        return _redirect_with_error("/", "Для режима 'ee' укажите домен для fake-TLS")

    service, init_error = _try_get_service()
    if init_error is not None:
        return _redirect_with_error("/", init_error)

    assert service is not None
    try:
        service.create_proxy(
            desired_port=desired_port,
            secret_mode=secret_mode,
            tls_domain=cleaned_domain,
        )
    except ProxyServiceError as exc:
        logger.error("Ошибка создания прокси: %s", exc)
        return _redirect_with_error("/", str(exc))
    return RedirectResponse(url="/", status_code=303)


@router.post("/proxies/{proxy_id}/delete", response_class=RedirectResponse)
async def delete_proxy(request: Request, proxy_id: int) -> RedirectResponse:
    """Удаляет MTProxy по идентификатору и возвращает на главную страницу."""
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    service, init_error = _try_get_service()
    if init_error is not None:
        return _redirect_with_error("/", init_error)

    assert service is not None
    try:
        service.delete_proxy(proxy_id)
    except ProxyServiceError as exc:
        logger.error("Ошибка удаления прокси id=%d: %s", proxy_id, exc)
        return _redirect_with_error("/", str(exc))
    return RedirectResponse(url="/", status_code=303)
