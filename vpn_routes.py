"""
HTTP-роуты для VPN/прокси-провайдеров (WireGuard, VLESS, ...).

Ни один обработчик здесь не знает про WireGuard/Xray/systemd/iptables —
только вызовы providers.get_provider(key) и рендер общего шаблона
provider.html. Добавление нового протокола (Shadowsocks, Hysteria2, ...)
не требует новых роутов: providers/registry.py регистрирует ключ, и он
автоматически получает /vpn/<key>, /vpn/<key>/clients и т.д.

MTProxy пока живёт в своём отдельном routes.py/templates/proxies.html —
у него другие поля настройки (secret_mode/tls_domain) и исторически
устоявшийся отдельный UX; providers.mtproxy_provider существует уже
сейчас и подтверждает, что интерфейс не завязан на WireGuard/VLESS,
но объединение MTProxy в общий шаблон — отдельная задача на будущее.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import auth
import config
from providers import get_provider, list_providers
from providers.base import ProviderError, VpnProvider
from utils import escape_html

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory=str(config.TEMPLATES_DIR))

# URL-путь для каждого провайдера — сохраняем исторические /wireguard и
# /vless (не /vpn/wireguard), чтобы не ломать закладки/навбар/тесты.
_URL_PREFIX: dict[str, str] = {
    "wireguard": "/wireguard",
    "vless": "/vless",
}


def _redirect_with_error(path: str, message: str) -> RedirectResponse:
    return RedirectResponse(url=f"{path}?error={escape_html(message)}", status_code=303)


def _try_get_provider(key: str) -> tuple[VpnProvider | None, str | None]:
    try:
        return get_provider(key), None
    except ProviderError as exc:
        logger.error("Не удалось инициализировать провайдер %r: %s", key, exc)
        return None, str(exc)


async def _provider_page(request: Request, key: str) -> HTMLResponse:
    url_prefix = _URL_PREFIX[key]
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    error_message = request.query_params.get("error")
    info_message = request.query_params.get("message")
    configured = False
    clients: list = []
    status = "missing"
    endpoint = ""
    primary_client = None
    diagnostics = None

    provider, init_error = _try_get_provider(key)
    if init_error is not None:
        error_message = init_error
    else:
        assert provider is not None
        try:
            primary_client = provider.ensure_ready()
        except ProviderError as exc:
            logger.error("%s.ensure_ready: %s", key, exc)
            error_message = str(exc)
        configured = provider.is_configured()
        if configured:
            clients = provider.list_clients()
            status = provider.status()
            endpoint = provider.endpoint()
            if primary_client is None and clients:
                primary_client = clients[0]
            try:
                diagnostics = provider.diagnostics()
            except Exception:  # noqa: BLE001 — диагностика не должна ронять страницу
                logger.exception("Ошибка диагностики провайдера %r", key)

    return templates.TemplateResponse(
        request=request,
        name="provider.html",
        context={
            "provider_key": key,
            "provider": provider,
            "url_prefix": url_prefix,
            "configured": configured,
            "clients": clients,
            "primary_client": primary_client,
            "status": status,
            "endpoint": endpoint,
            "diagnostics": diagnostics,
            "setup_fields": provider.setup_fields() if provider else [],
            "error_message": error_message,
            "info_message": info_message,
            "username": request.session.get(auth.SESSION_USER_KEY),
        },
    )


async def _provider_setup(request: Request, key: str) -> RedirectResponse:
    url_prefix = _URL_PREFIX[key]
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    form = await request.form()
    provider, init_error = _try_get_provider(key)
    if init_error is not None:
        return _redirect_with_error(url_prefix, init_error)

    assert provider is not None
    try:
        provider.setup(**{k: str(v) for k, v in form.items()})
    except ProviderError as exc:
        logger.error("Ошибка настройки %s: %s", key, exc)
        return _redirect_with_error(url_prefix, str(exc))
    return RedirectResponse(url=f"{url_prefix}?message=Сервер+настроен", status_code=303)


async def _provider_add_client(request: Request, key: str) -> RedirectResponse:
    url_prefix = _URL_PREFIX[key]
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    form = await request.form()
    name = str(form.get("name", "")).strip()
    if not name:
        return _redirect_with_error(url_prefix, "Укажите имя устройства")

    provider, init_error = _try_get_provider(key)
    if init_error is not None:
        return _redirect_with_error(url_prefix, init_error)

    assert provider is not None
    try:
        provider.add_client(name)
    except ProviderError as exc:
        logger.error("Ошибка добавления клиента %s: %s", key, exc)
        return _redirect_with_error(url_prefix, str(exc))
    return RedirectResponse(url=url_prefix, status_code=303)


async def _provider_delete_client(request: Request, key: str, client_id: str) -> RedirectResponse:
    url_prefix = _URL_PREFIX[key]
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    provider, init_error = _try_get_provider(key)
    if init_error is not None:
        return _redirect_with_error(url_prefix, init_error)

    assert provider is not None
    try:
        provider.delete_client(client_id)
    except ProviderError as exc:
        logger.error("Ошибка удаления клиента %s/%s: %s", key, client_id, exc)
        return _redirect_with_error(url_prefix, str(exc))
    return RedirectResponse(url=url_prefix, status_code=303)


async def _provider_restart(request: Request, key: str) -> RedirectResponse:
    url_prefix = _URL_PREFIX[key]
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    provider, init_error = _try_get_provider(key)
    if init_error is not None:
        return _redirect_with_error(url_prefix, init_error)

    assert provider is not None
    try:
        provider.restart()
    except ProviderError as exc:
        logger.error("Ошибка перезапуска %s: %s", key, exc)
        return _redirect_with_error(url_prefix, str(exc))
    return RedirectResponse(url=f"{url_prefix}?message=Сервер+перезапущен", status_code=303)


async def _provider_reset(request: Request, key: str) -> RedirectResponse:
    url_prefix = _URL_PREFIX[key]
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    provider, init_error = _try_get_provider(key)
    if init_error is not None:
        return _redirect_with_error(url_prefix, init_error)

    assert provider is not None
    try:
        provider.reset()
    except ProviderError as exc:
        logger.error("Ошибка сброса %s: %s", key, exc)
        return _redirect_with_error(url_prefix, str(exc))
    return RedirectResponse(
        url=f"{url_prefix}?message=Конфигурация+сброшена+—+настройте+сервер+заново", status_code=303,
    )


async def _provider_download_client(request: Request, key: str, client_id: str) -> HTMLResponse:
    url_prefix = _URL_PREFIX[key]
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    provider, init_error = _try_get_provider(key)
    if init_error is not None:
        return _redirect_with_error(url_prefix, init_error)

    assert provider is not None
    clients = {c.id: c for c in provider.list_clients()}
    client = clients.get(client_id)
    if client is None:
        return _redirect_with_error(url_prefix, "Клиент не найден")

    return PlainTextResponse(
        client.config_text,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{client.name}.conf"'},
    )


# ---------------------------------------------------------------------------
# WireGuard — тонкие обёртки над generic-обработчиками (сохраняют URL)
# ---------------------------------------------------------------------------
@router.get("/wireguard", response_class=HTMLResponse)
async def wireguard_page(request: Request) -> HTMLResponse:
    return await _provider_page(request, "wireguard")


@router.post("/wireguard/setup")
async def wireguard_setup(request: Request):
    return await _provider_setup(request, "wireguard")


@router.post("/wireguard/peers")
async def wireguard_add_peer(request: Request):
    return await _provider_add_client(request, "wireguard")


@router.post("/wireguard/peers/{peer_id}/delete")
async def wireguard_delete_peer(request: Request, peer_id: str):
    return await _provider_delete_client(request, "wireguard", peer_id)


@router.post("/wireguard/restart")
async def wireguard_restart(request: Request):
    return await _provider_restart(request, "wireguard")


@router.post("/wireguard/reset")
async def wireguard_reset(request: Request):
    return await _provider_reset(request, "wireguard")


@router.get("/wireguard/peers/{peer_id}/download")
async def wireguard_download_peer(request: Request, peer_id: str):
    return await _provider_download_client(request, "wireguard", peer_id)


# ---------------------------------------------------------------------------
# VLESS — тонкие обёртки над generic-обработчиками (сохраняют URL)
# ---------------------------------------------------------------------------
@router.get("/vless", response_class=HTMLResponse)
async def vless_page(request: Request) -> HTMLResponse:
    return await _provider_page(request, "vless")


@router.post("/vless/setup")
async def vless_setup(request: Request):
    return await _provider_setup(request, "vless")


@router.post("/vless/clients")
async def vless_add_client(request: Request):
    return await _provider_add_client(request, "vless")


@router.post("/vless/clients/{client_id}/delete")
async def vless_delete_client(request: Request, client_id: str):
    return await _provider_delete_client(request, "vless", client_id)


@router.post("/vless/restart")
async def vless_restart(request: Request):
    return await _provider_restart(request, "vless")


@router.post("/vless/reset")
async def vless_reset(request: Request):
    return await _provider_reset(request, "vless")


# ---------------------------------------------------------------------------
# Общий статус для автообновления (все зарегистрированные провайдеры)
# ---------------------------------------------------------------------------
@router.get("/api/vpn-status")
async def api_vpn_status(request: Request) -> JSONResponse:
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return JSONResponse({"detail": "unauthorized"}, status_code=401)

    result: dict[str, str] = {}
    for key in list_providers():
        if key == "mtproxy":
            continue  # у MTProxy отдельная страница/модель статуса
        provider, _init_error = _try_get_provider(key)
        result[key] = provider.status() if provider and provider.is_configured() else "missing"
    return JSONResponse(result)
