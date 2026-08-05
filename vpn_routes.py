"""
HTTP-роуты для VPN-подсистем: WireGuard и Xray/VLESS.
Только вызовы vpn_service.py — никакой бизнес-логики здесь.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import auth
import config
from utils import escape_html
from vpn_service import VpnServiceError, WireGuardService, XrayService

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory=str(config.TEMPLATES_DIR))


def _redirect_with_error(path: str, message: str) -> RedirectResponse:
    return RedirectResponse(url=f"{path}?error={escape_html(message)}", status_code=303)


def _try_get_wg_service() -> tuple[WireGuardService | None, str | None]:
    try:
        return WireGuardService(), None
    except VpnServiceError as exc:
        logger.error("Не удалось инициализировать WireGuardService: %s", exc)
        return None, str(exc)


def _try_get_xray_service() -> tuple[XrayService | None, str | None]:
    try:
        return XrayService(), None
    except VpnServiceError as exc:
        logger.error("Не удалось инициализировать XrayService: %s", exc)
        return None, str(exc)


# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------
@router.get("/wireguard", response_class=HTMLResponse)
async def wireguard_page(request: Request) -> HTMLResponse:
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    error_message = request.query_params.get("error")
    info_message = request.query_params.get("message")
    server_config = None
    peers = []
    status = "missing"
    connection_labels: dict[int, str] = {}
    traffic_labels: dict[int, str] = {}
    primary_peer = None

    service, init_error = _try_get_wg_service()
    if init_error is not None:
        error_message = init_error
    else:
        assert service is not None
        try:
            primary_peer = service.ensure_ready()
        except VpnServiceError as exc:
            logger.error("WG ensure_ready: %s", exc)
            error_message = str(exc)
        server_config = service.get_server_config()
        if server_config is not None:
            peers = service.list_peers()
            status = service.get_status()
            connection_labels = service.get_peer_connection_labels()
            traffic_labels = service.get_peer_traffic_labels()
            if primary_peer is None and peers:
                primary_peer = peers[0]

    return templates.TemplateResponse(
        request=request,
        name="wireguard.html",
        context={
            "server_config": server_config,
            "peers": peers,
            "primary_peer": primary_peer,
            "status": status,
            "connection_labels": connection_labels,
            "traffic_labels": traffic_labels,
            "error_message": error_message,
            "info_message": info_message,
            "username": request.session.get(auth.SESSION_USER_KEY),
            "default_port": config.WG_DEFAULT_PORT,
            "default_subnet": config.WG_DEFAULT_SUBNET,
            "default_dns": config.WG_DEFAULT_DNS,
        },
    )


@router.post("/wireguard/setup")
async def wireguard_setup(
    request: Request,
    listen_port: str = Form(str(config.WG_DEFAULT_PORT)),
    subnet: str = Form(config.WG_DEFAULT_SUBNET),
    dns: str = Form(config.WG_DEFAULT_DNS),
):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    cleaned_port = listen_port.strip()
    if not cleaned_port.isdigit():
        return _redirect_with_error("/wireguard", "Укажите корректный номер порта")

    service, init_error = _try_get_wg_service()
    if init_error is not None:
        return _redirect_with_error("/wireguard", init_error)

    assert service is not None
    try:
        service.setup_server(listen_port=int(cleaned_port), subnet=subnet.strip(), dns=dns.strip())
    except VpnServiceError as exc:
        logger.error("Ошибка настройки WireGuard-сервера: %s", exc)
        return _redirect_with_error("/wireguard", str(exc))
    return RedirectResponse(url="/wireguard?message=WireGuard-сервер+настроен", status_code=303)


@router.post("/wireguard/peers")
async def wireguard_add_peer(request: Request, name: str = Form(...)):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    service, init_error = _try_get_wg_service()
    if init_error is not None:
        return _redirect_with_error("/wireguard", init_error)

    assert service is not None
    try:
        service.add_peer(name)
    except VpnServiceError as exc:
        logger.error("Ошибка добавления WireGuard peer: %s", exc)
        return _redirect_with_error("/wireguard", str(exc))
    return RedirectResponse(url="/wireguard", status_code=303)


@router.post("/wireguard/peers/{peer_id}/delete")
async def wireguard_delete_peer(request: Request, peer_id: int):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    service, init_error = _try_get_wg_service()
    if init_error is not None:
        return _redirect_with_error("/wireguard", init_error)

    assert service is not None
    try:
        service.delete_peer(peer_id)
    except VpnServiceError as exc:
        logger.error("Ошибка удаления WireGuard peer id=%d: %s", peer_id, exc)
        return _redirect_with_error("/wireguard", str(exc))
    return RedirectResponse(url="/wireguard", status_code=303)


@router.post("/wireguard/restart")
async def wireguard_restart(request: Request):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    service, init_error = _try_get_wg_service()
    if init_error is not None:
        return _redirect_with_error("/wireguard", init_error)

    assert service is not None
    try:
        service.restart_server()
    except VpnServiceError as exc:
        logger.error("Ошибка перезапуска WireGuard-сервера: %s", exc)
        return _redirect_with_error("/wireguard", str(exc))
    return RedirectResponse(url="/wireguard?message=Сервер+перезапущен", status_code=303)


@router.post("/wireguard/reset")
async def wireguard_reset(request: Request):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    service, init_error = _try_get_wg_service()
    if init_error is not None:
        return _redirect_with_error("/wireguard", init_error)

    assert service is not None
    try:
        service.reset_server()
    except VpnServiceError as exc:
        logger.error("Ошибка сброса конфигурации WireGuard: %s", exc)
        return _redirect_with_error("/wireguard", str(exc))
    return RedirectResponse(url="/wireguard?message=Конфигурация+сброшена+—+настройте+сервер+заново", status_code=303)


@router.get("/wireguard/peers/{peer_id}/download")
async def wireguard_download_peer(request: Request, peer_id: int):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    service, init_error = _try_get_wg_service()
    if init_error is not None:
        return _redirect_with_error("/wireguard", init_error)

    assert service is not None
    peers = {p.id: p for p in service.list_peers()}
    peer = peers.get(peer_id)
    if peer is None:
        return _redirect_with_error("/wireguard", "Peer не найден")

    return PlainTextResponse(
        peer.config_text,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{peer.name}.conf"'},
    )


# ---------------------------------------------------------------------------
# Xray / VLESS
# ---------------------------------------------------------------------------
@router.get("/vless", response_class=HTMLResponse)
async def vless_page(request: Request) -> HTMLResponse:
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    error_message = request.query_params.get("error")
    info_message = request.query_params.get("message")
    server_config = None
    clients = []
    status = "missing"

    service, init_error = _try_get_xray_service()
    if init_error is not None:
        error_message = init_error
    else:
        assert service is not None
        try:
            service.ensure_ready()
        except VpnServiceError as exc:
            logger.error("Xray ensure_ready: %s", exc)
            error_message = str(exc)
        server_config = service.get_server_config()
        if server_config is not None:
            clients = service.list_clients()
            status = service.get_status()

    return templates.TemplateResponse(
        request=request,
        name="vless.html",
        context={
            "server_config": server_config,
            "clients": clients,
            "status": status,
            "error_message": error_message,
            "info_message": info_message,
            "username": request.session.get(auth.SESSION_USER_KEY),
            "default_port": config.XRAY_DEFAULT_PORT,
            "default_dest": config.XRAY_DEFAULT_DEST,
            "default_server_name": config.XRAY_DEFAULT_SERVER_NAMES[0],
        },
    )


@router.post("/vless/setup")
async def vless_setup(
    request: Request,
    listen_port: str = Form(str(config.XRAY_DEFAULT_PORT)),
    dest: str = Form(config.XRAY_DEFAULT_DEST),
    server_name: str = Form(config.XRAY_DEFAULT_SERVER_NAMES[0]),
):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    cleaned_port = listen_port.strip()
    if not cleaned_port.isdigit():
        return _redirect_with_error("/vless", "Укажите корректный номер порта")
    if not dest.strip() or ":" not in dest:
        return _redirect_with_error("/vless", "Укажите dest в формате домен:порт, например www.microsoft.com:443")

    service, init_error = _try_get_xray_service()
    if init_error is not None:
        return _redirect_with_error("/vless", init_error)

    assert service is not None
    try:
        service.setup_server(listen_port=int(cleaned_port), dest=dest.strip(), server_name=server_name.strip())
    except VpnServiceError as exc:
        logger.error("Ошибка настройки Xray-сервера: %s", exc)
        return _redirect_with_error("/vless", str(exc))
    return RedirectResponse(url="/vless?message=Xray-сервер+настроен", status_code=303)


@router.post("/vless/clients")
async def vless_add_client(request: Request, name: str = Form(...)):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    service, init_error = _try_get_xray_service()
    if init_error is not None:
        return _redirect_with_error("/vless", init_error)

    assert service is not None
    try:
        service.add_client(name)
    except VpnServiceError as exc:
        logger.error("Ошибка добавления VLESS-клиента: %s", exc)
        return _redirect_with_error("/vless", str(exc))
    return RedirectResponse(url="/vless", status_code=303)


@router.post("/vless/clients/{client_id}/delete")
async def vless_delete_client(request: Request, client_id: int):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    service, init_error = _try_get_xray_service()
    if init_error is not None:
        return _redirect_with_error("/vless", init_error)

    assert service is not None
    try:
        service.delete_client(client_id)
    except VpnServiceError as exc:
        logger.error("Ошибка удаления VLESS-клиента id=%d: %s", client_id, exc)
        return _redirect_with_error("/vless", str(exc))
    return RedirectResponse(url="/vless", status_code=303)


@router.post("/vless/restart")
async def vless_restart(request: Request):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    service, init_error = _try_get_xray_service()
    if init_error is not None:
        return _redirect_with_error("/vless", init_error)

    assert service is not None
    try:
        service.restart_server()
    except VpnServiceError as exc:
        logger.error("Ошибка перезапуска Xray-сервера: %s", exc)
        return _redirect_with_error("/vless", str(exc))
    return RedirectResponse(url="/vless?message=Сервер+перезапущен", status_code=303)


@router.post("/vless/reset")
async def vless_reset(request: Request):
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    service, init_error = _try_get_xray_service()
    if init_error is not None:
        return _redirect_with_error("/vless", init_error)

    assert service is not None
    try:
        service.reset_server()
    except VpnServiceError as exc:
        logger.error("Ошибка сброса конфигурации Xray: %s", exc)
        return _redirect_with_error("/vless", str(exc))
    return RedirectResponse(url="/vless?message=Конфигурация+сброшена+—+настройте+сервер+заново", status_code=303)


# ---------------------------------------------------------------------------
# Общий статус для автообновления (VPN)
# ---------------------------------------------------------------------------
@router.get("/api/vpn-status")
async def api_vpn_status(request: Request) -> JSONResponse:
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return JSONResponse({"detail": "unauthorized"}, status_code=401)

    wg_status = "missing"
    xray_status = "missing"

    wg_service, wg_err = _try_get_wg_service()
    if wg_service is not None and wg_service.get_server_config() is not None:
        wg_status = wg_service.get_status()

    xray_service, xray_err = _try_get_xray_service()
    if xray_service is not None and xray_service.get_server_config() is not None:
        xray_status = xray_service.get_status()

    return JSONResponse({"wireguard": wg_status, "vless": xray_status})
