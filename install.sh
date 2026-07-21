#!/usr/bin/env bash
#
# install.sh — полностью автоматическая установка MTProxy Control Panel
# на Ubuntu Server. Устанавливает Docker и Python при отсутствии,
# создаёт venv, ставит зависимости, запускает FastAPI и проверяет,
# что сервис действительно отвечает.
#
# Запуск: bash install.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# Константы
# ---------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly VENV_DIR="${SCRIPT_DIR}/venv"
readonly PID_FILE="${SCRIPT_DIR}/run.pid"
readonly APP_LOG="${SCRIPT_DIR}/logs/uvicorn.log"
readonly APP_HOST="0.0.0.0"
readonly APP_PORT="8000"
readonly HEALTHCHECK_URL="http://127.0.0.1:${APP_PORT}/"
readonly HEALTHCHECK_TIMEOUT_SECONDS=30
readonly PYTHON_MIN_MAJOR=3
readonly PYTHON_MIN_MINOR=10

log() {
    printf '[install.sh] %s\n' "$1"
}

fail() {
    printf '[install.sh] ОШИБКА: %s\n' "$1" >&2
    exit 1
}

require_root_or_sudo() {
    if [[ "${EUID}" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
        fail "Скрипт требует root-доступ либо установленный sudo."
    fi
}

as_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# ---------------------------------------------------------------------------
# 1. Установка Python, если отсутствует
# ---------------------------------------------------------------------------
ensure_python() {
    local need_install=0

    if command -v python3 >/dev/null 2>&1; then
        local version major minor
        version="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
        major="${version%%.*}"
        minor="${version##*.}"
        if (( major > PYTHON_MIN_MAJOR || (major == PYTHON_MIN_MAJOR && minor >= PYTHON_MIN_MINOR) )); then
            log "Python ${version} уже установлен."
        else
            log "Найден Python ${version}, требуется >= ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}."
            need_install=1
        fi
    else
        log "Python3 не найден."
        need_install=1
    fi

    # На минимальных образах Ubuntu python3 может быть предустановлен,
    # но пакет с модулем venv (python3-venv / python3.X-venv) — нет.
    # Поэтому проверяем venv отдельно, независимо от версии Python.
    if ! python3 -m venv --help >/dev/null 2>&1; then
        log "Модуль 'venv' недоступен для текущего python3."
        need_install=1
    fi

    if ! python3 -m pip --version >/dev/null 2>&1; then
        log "Модуль 'pip' недоступен для текущего python3."
        need_install=1
    fi

    if (( need_install == 0 )); then
        return
    fi

    log "Устанавливаю python3, python3-venv, python3-pip."
    as_root apt-get update -y

    local py_minor_pkg="python3.$(python3 -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo '')"

    # Ставим и универсальные, и версионные пакеты (например python3.12-venv),
    # т.к. на разных релизах Ubuntu имя пакета для venv отличается.
    # apt-get install игнорирует не найденные версионные имена мягко только
    # если явно допустить ошибку -- поэтому пробуем по отдельности.
    as_root apt-get install -y python3 python3-venv python3-pip
    if [[ -n "${py_minor_pkg}" && "${py_minor_pkg}" != "python3." ]]; then
        as_root apt-get install -y "${py_minor_pkg}-venv" 2>/dev/null || true
    fi

    if ! python3 -m venv --help >/dev/null 2>&1; then
        fail "Не удалось установить рабочий модуль venv для python3. Установите вручную: apt install python3-venv (или python3.X-venv) и запустите install.sh снова."
    fi
}

# ---------------------------------------------------------------------------
# 2. Установка Docker, если отсутствует
# ---------------------------------------------------------------------------
ensure_docker() {
    if command -v docker >/dev/null 2>&1; then
        log "Docker уже установлен: $(docker --version)"
    else
        log "Docker не найден. Устанавливаю через официальный скрипт get-docker.sh."
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
        as_root sh /tmp/get-docker.sh
        rm -f /tmp/get-docker.sh
    fi

    if ! as_root systemctl is-active --quiet docker 2>/dev/null; then
        log "Запускаю Docker daemon."
        as_root systemctl enable docker >/dev/null 2>&1 || true
        as_root systemctl start docker || as_root service docker start
    fi

    if [[ "${EUID}" -ne 0 ]] && ! groups "${USER}" | grep -q docker; then
        log "Добавляю пользователя '${USER}' в группу docker."
        as_root usermod -aG docker "${USER}"
        log "ВНИМАНИЕ: чтобы членство в группе docker вступило в силу без " \
            "перезахода, установка продолжится через 'sudo docker' и venv " \
            "будет запущен с sudo для доступа к Docker daemon в этой сессии."
        readonly USE_SUDO_FOR_APP=1
    else
        readonly USE_SUDO_FOR_APP=0
    fi

    # Финальная проверка доступности daemon.
    if ! as_root docker info >/dev/null 2>&1; then
        fail "Docker daemon не отвечает после установки/запуска."
    fi
}

# ---------------------------------------------------------------------------
# 3. Создание структуры проекта (директории создаются и в config.py,
#    но гарантируем их наличие до старта, чтобы установка была явной)
# ---------------------------------------------------------------------------
ensure_project_structure() {
    log "Создаю структуру каталогов проекта."
    mkdir -p "${SCRIPT_DIR}/data" \
             "${SCRIPT_DIR}/logs" \
             "${SCRIPT_DIR}/static/qr" \
             "${SCRIPT_DIR}/templates"
}

# ---------------------------------------------------------------------------
# 4. Виртуальное окружение и зависимости
# ---------------------------------------------------------------------------
ensure_venv() {
    if [[ ! -d "${VENV_DIR}" ]]; then
        log "Создаю виртуальное окружение."
        python3 -m venv "${VENV_DIR}"
    else
        log "Виртуальное окружение уже существует."
    fi

    log "Устанавливаю зависимости из requirements.txt."
    "${VENV_DIR}/bin/pip" install --upgrade pip --quiet
    "${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt" --quiet
}

# ---------------------------------------------------------------------------
# 5. Запуск FastAPI-приложения в фоне (без systemd)
# ---------------------------------------------------------------------------
stop_existing_instance() {
    if [[ -f "${PID_FILE}" ]]; then
        local old_pid
        old_pid="$(cat "${PID_FILE}")"
        if kill -0 "${old_pid}" 2>/dev/null; then
            log "Останавливаю ранее запущенный экземпляр приложения (PID ${old_pid})."
            kill "${old_pid}" || true
            sleep 2
        fi
        rm -f "${PID_FILE}"
    fi
}

start_application() {
    log "Запускаю FastAPI-приложение через uvicorn."
    cd "${SCRIPT_DIR}"

    local run_cmd=("${VENV_DIR}/bin/uvicorn" main:app --host "${APP_HOST}" --port "${APP_PORT}")

    if [[ "${USE_SUDO_FOR_APP:-0}" -eq 1 ]]; then
        nohup sudo "${run_cmd[@]}" > "${APP_LOG}" 2>&1 &
    else
        nohup "${run_cmd[@]}" > "${APP_LOG}" 2>&1 &
    fi

    echo $! > "${PID_FILE}"
    log "Приложение запущено, PID=$(cat "${PID_FILE}"), логи: ${APP_LOG}"
}

# ---------------------------------------------------------------------------
# 6. Проверка успешного запуска
# ---------------------------------------------------------------------------
wait_for_healthcheck() {
    log "Ожидаю ответа сервиса на ${HEALTHCHECK_URL} (до ${HEALTHCHECK_TIMEOUT_SECONDS}с)."
    local waited=0
    while (( waited < HEALTHCHECK_TIMEOUT_SECONDS )); do
        # -L: панель теперь требует авторизацию и редиректит "/" -> "/login",
        # поэтому проверяем именно конечную страницу, куда попадёт браузер.
        if curl -fsSL -o /tmp/mtproxy_healthcheck.html -w '%{http_code}' \
            "${HEALTHCHECK_URL}" 2>/dev/null | grep -q '^200$'; then
            if grep -qi '<html' /tmp/mtproxy_healthcheck.html; then
                log "Сервис отвечает HTTP 200 и отдаёт HTML. Установка успешна."
                rm -f /tmp/mtproxy_healthcheck.html
                return 0
            fi
        fi
        sleep 1
        (( waited += 1 ))
    done
    return 1
}

verify_docker_ps() {
    if ! as_root docker ps >/dev/null 2>&1; then
        fail "Команда 'docker ps' завершилась ошибкой после установки."
    fi
    log "Проверка 'docker ps' пройдена."
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
    require_root_or_sudo
    ensure_python
    ensure_docker
    ensure_project_structure
    ensure_venv
    stop_existing_instance
    start_application

    if ! wait_for_healthcheck; then
        log "Сервис не ответил корректно. Последние строки лога:"
        tail -n 50 "${APP_LOG}" >&2 || true
        fail "Проверка HTTP 200 на ${HEALTHCHECK_URL} не пройдена. Установка прервана."
    fi

    verify_docker_ps

    log "==============================================================="
    log " MTProxy Control Panel установлена и запущена."
    log " Откройте в браузере: http://<IP_ЭТОГО_СЕРВЕРА>:${APP_PORT}/"
    if grep -q "СОЗДАНА ПЕРВАЯ УЧЁТНАЯ ЗАПИСЬ" "${APP_LOG}" 2>/dev/null; then
        log " Учётные данные администратора (показываются один раз):"
        grep -A 3 "Логин:" "${APP_LOG}" | tail -n 3 | sed 's/^/   /'
    else
        log " Учётная запись администратора уже существует (пароль не менялся)."
    fi
    log " Логи приложения: ${APP_LOG}"
    log " PID процесса:    $(cat "${PID_FILE}")"
    log " Остановить:      kill \$(cat ${PID_FILE})"
    log "==============================================================="
}

main "$@"
