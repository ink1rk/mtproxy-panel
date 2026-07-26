"""
Веб-просмотрщик логов приложения. Позволяет смотреть последние строки
логов прямо в панели — без необходимости заходить на сервер по SSH.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

import auth
import config
from container_logs import get_container_logs, list_log_sources

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory=str(config.TEMPLATES_DIR))

MAX_RETURNED_LINES = 1000
DEFAULT_RETURNED_LINES = 200


def _read_tail_lines(path, max_lines: int) -> list[str]:
    """Читает последние max_lines строк файла, устойчиво к большим файлам."""
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            # Простая и надёжная реализация: файлы логов ограничены
            # RotatingFileHandler (config.LOG_MAX_BYTES), так что чтение
            # целиком безопасно по памяти.
            lines = f.readlines()
        return [line.rstrip("\n") for line in lines[-max_lines:]]
    except OSError as exc:
        logger.error("Не удалось прочитать лог-файл %s: %s", path, exc)
        return [f"[ошибка чтения файла: {exc}]"]


@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request) -> HTMLResponse:
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return redirect

    return templates.TemplateResponse(
        request=request,
        name="logs.html",
        context={"username": request.session.get(auth.SESSION_USER_KEY)},
    )


def _filter_lines(all_lines: list[str], level_filter: str, search_filter: str) -> list[str]:
    filtered = all_lines
    if level_filter:
        filtered = [line for line in filtered if f"| {level_filter}" in line or f"|{level_filter}" in line]
    if search_filter:
        filtered = [line for line in filtered if search_filter in line.lower()]
    return filtered


@router.get("/api/logs")
async def api_logs(request: Request) -> JSONResponse:
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return JSONResponse({"detail": "unauthorized"}, status_code=401)

    query = request.query_params
    try:
        lines_count = min(int(query.get("lines", DEFAULT_RETURNED_LINES)), MAX_RETURNED_LINES)
    except ValueError:
        lines_count = DEFAULT_RETURNED_LINES
    level_filter = (query.get("level") or "").strip().upper()
    search_filter = (query.get("q") or "").strip().lower()
    source = (query.get("source") or "panel").strip()

    if source == "panel":
        all_lines = _read_tail_lines(config.LOG_FILE_PATH, MAX_RETURNED_LINES)
    else:
        known_names = {s.name for s in list_log_sources()}
        if source not in known_names:
            return JSONResponse({"detail": "неизвестный источник логов"}, status_code=404)
        all_lines = get_container_logs(source, tail=MAX_RETURNED_LINES)

    filtered = _filter_lines(all_lines, level_filter, search_filter)
    return JSONResponse({"lines": filtered[-lines_count:], "total_available": len(all_lines)})


@router.get("/api/log-sources")
async def api_log_sources(request: Request) -> JSONResponse:
    """Список доступных источников логов (панель + текущие MTProxy/WireGuard/Xray контейнеры)."""
    redirect = auth.require_login_redirect(request)
    if redirect is not None:
        return JSONResponse({"detail": "unauthorized"}, status_code=401)

    sources = [{"name": "panel", "label": "Панель (app.log)"}]
    sources.extend({"name": s.name, "label": s.label} for s in list_log_sources())
    return JSONResponse({"sources": sources})
