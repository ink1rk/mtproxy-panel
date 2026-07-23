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
# 0. Синхронизация кода с origin (защита от рассинхрона файлов при повторном
#    запуске install.sh на уже установленном сервере: код в шаблонах и
#    роутах должен всегда браться из одного и того же коммита).
# ---------------------------------------------------------------------------
ensure_repo_up_to_date() {
    if [[ ! -d "${SCRIPT_DIR}/.git" ]]; then
        log "Каталог '${SCRIPT_DIR}' не является git-репозиторием — пропускаю синхронизацию с origin."
        log "Рекомендуется устанавливать панель через 'git clone', чтобы обновления подтягивались автоматически."
        return
    fi

    if ! command -v git >/dev/null 2>&1; then
        log "git не найден, пропускаю синхронизацию с origin."
        return
    fi

    local branch
    branch="$(git -C "${SCRIPT_DIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '')"
    if [[ -z "${branch}" || "${branch}" == "HEAD" ]]; then
        log "Не удалось определить текущую ветку git, пропускаю синхронизацию с origin."
        return
    fi

    if ! git -C "${SCRIPT_DIR}" diff --quiet || ! git -C "${SCRIPT_DIR}" diff --cached --quiet; then
        log "В рабочей копии есть несохранённые изменения — пропускаю синхронизацию с origin " \
            "(чтобы не потерять локальные правки). Если это плановое обновление, сначала " \
            "закоммитьте или отмените изменения ('git status')."
        return
    fi

    log "Проверяю обновления в origin/${branch}."
    if ! git -C "${SCRIPT_DIR}" fetch --quiet origin "${branch}"; then
        log "Не удалось связаться с origin (нет сети?) — продолжаю установку с текущим " \
            "состоянием рабочей копии."
        return
    fi

    if ! git -C "${SCRIPT_DIR}" rev-parse --verify --quiet "origin/${branch}" >/dev/null; then
        log "Ветка '${branch}' отсутствует в origin — пропускаю синхронизацию."
        return
    fi

    if git -C "${SCRIPT_DIR}" merge-base --is-ancestor "origin/${branch}" HEAD; then
        log "Локальный код уже не старше origin/${branch} — синхронизация не требуется."
        return
    fi

    # ВАЖНО: hard-reset делаем ТОЛЬКО если это чистый fast-forward, то есть текущий
    # HEAD является предком origin/<branch>. Если в рабочей копии есть локальные
    # коммиты, которых нет в origin (например, сделанные прямо на сервере и ещё не
    # запушенные), 'git reset --hard' их бы молча уничтожил — именно так ранее была
    # потеряна диагностика, добавленная прямо на сервере. В таком случае синхронизацию
    # пропускаем и явно предупреждаем, вместо того чтобы стирать чужую работу.
    if ! git -C "${SCRIPT_DIR}" merge-base --is-ancestor HEAD "origin/${branch}"; then
        log "ВНИМАНИЕ: в рабочей копии есть локальные коммиты, которых нет в origin/${branch}. " \
            "Чтобы не потерять их, автоматическая синхронизация ПРОПУЩЕНА. Если это осознанные " \
            "локальные изменения — запушьте их в origin ('git push'), либо выполните " \
            "'git reset --hard origin/${branch}' вручную, чтобы явно их отбросить."
        return
    fi

    log "Синхронизирую код с origin/${branch} (fast-forward)."
    if git -C "${SCRIPT_DIR}" reset --quiet --hard "origin/${branch}"; then
        log "Код обновлён до последнего коммита origin/${branch}."
    else
        log "Не удалось синхронизировать код с origin — продолжаю установку с текущим " \
            "состоянием рабочей копии."
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
find_pids_on_app_port() {
    # Возвращает PID-ы всех процессов, слушающих APP_PORT, независимо от того,
    # что записано в PID_FILE. Пробуем несколько инструментов по очереди,
    # т.к. набор утилит отличается между минимальными образами Ubuntu.
    local port="$1" pids=""
    if command -v ss >/dev/null 2>&1; then
        pids="$(as_root ss -ltnp 2>/dev/null | awk -v p=":${port}$" '$4 ~ p' \
            | grep -oP 'pid=\K[0-9]+' | sort -u)"
    fi
    if [[ -z "${pids}" ]] && command -v fuser >/dev/null 2>&1; then
        pids="$(as_root fuser -n tcp "${port}" 2>/dev/null | tr -s ' \t' '\n' \
            | grep -E '^[0-9]+$' | sort -u)"
    fi
    if [[ -z "${pids}" ]] && command -v lsof >/dev/null 2>&1; then
        pids="$(as_root lsof -ti "tcp:${port}" 2>/dev/null | sort -u)"
    fi
    if [[ -z "${pids}" ]] && command -v netstat >/dev/null 2>&1; then
        pids="$(as_root netstat -ltnp 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {print $NF}' \
            | grep -oE '^[0-9]+' | sort -u)"
    fi
    printf '%s' "${pids}"
}

wait_for_pid_exit() {
    local pid="$1" timeout="$2" waited=0
    while kill -0 "${pid}" 2>/dev/null && (( waited < timeout )); do
        sleep 1
        (( waited += 1 ))
    done
}

stop_existing_instance() {
    if [[ -f "${PID_FILE}" ]]; then
        local old_pid
        old_pid="$(cat "${PID_FILE}")"
        if kill -0 "${old_pid}" 2>/dev/null; then
            log "Останавливаю ранее запущенный экземпляр приложения (PID ${old_pid})."
            kill "${old_pid}" || true
            wait_for_pid_exit "${old_pid}" 10
        fi
        rm -f "${PID_FILE}"
    fi

    # ВАЖНО: PID_FILE может рассинхронизироваться с реальностью (сбой между
    # запусками, переиспользование номера PID, ручной запуск мимо install.sh
    # и т.п.) — тогда описанный выше kill никого не остановит, порт останется
    # занят "забытым" процессом со старым кодом, а health-check ниже всё равно
    # получит HTTP 200 от него и install.sh решит, что всё в порядке. Поэтому
    # независимо от PID_FILE явно проверяем, кто слушает APP_PORT, и добиваем
    # таких "зомби" перед запуском нового экземпляра.
    local stale_pids
    stale_pids="$(find_pids_on_app_port "${APP_PORT}")"
    if [[ -n "${stale_pids}" ]]; then
        log "Порт ${APP_PORT} всё ещё занят процессом(ами) [${stale_pids//$'\n'/, }], не учтённым(и) в run.pid — останавливаю."
        local pid
        for pid in ${stale_pids}; do
            as_root kill "${pid}" 2>/dev/null || true
        done
        sleep 2
        stale_pids="$(find_pids_on_app_port "${APP_PORT}")"
        if [[ -n "${stale_pids}" ]]; then
            log "Процесс(ы) [${stale_pids//$'\n'/, }] не завершились по SIGTERM, убиваю принудительно (kill -9)."
            for pid in ${stale_pids}; do
                as_root kill -9 "${pid}" 2>/dev/null || true
            done
            sleep 1
        fi
    fi
}

clear_python_bytecode_cache() {
    # На случай обновления кода без переустановки venv: гарантируем, что
    # интерпретатор не подхватит устаревшие .pyc из предыдущей версии кода.
    log "Очищаю кеш скомпилированных .pyc-файлов приложения."
    find "${SCRIPT_DIR}" -maxdepth 4 -type d -name "__pycache__" \
        -not -path "${VENV_DIR}/*" -exec rm -rf {} + 2>/dev/null || true
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

verify_started_process_owns_port() {
    # Здоровый HTTP 200 сам по себе не гарантирует, что отвечает именно
    # процесс, который мы только что запустили (см. find_pids_on_app_port) —
    # он мог получить ответ от "забытого" старого процесса на том же порту.
    # Явно сверяем PID из run.pid с тем, что реально слушает APP_PORT.
    local expected_pid actual_pids
    expected_pid="$(cat "${PID_FILE}" 2>/dev/null || echo '')"
    actual_pids="$(find_pids_on_app_port "${APP_PORT}")"

    if [[ -z "${actual_pids}" ]]; then
        log "ПРЕДУПРЕЖДЕНИЕ: не удалось определить, какой процесс слушает порт ${APP_PORT} " \
            "(нет ss/fuser/lsof?) — пропускаю проверку соответствия PID."
        return
    fi

    if ! grep -qx "${expected_pid}" <<< "${actual_pids}"; then
        fail "Порт ${APP_PORT} отвечает, но слушает его PID [${actual_pids//$'\n'/, }], а не " \
            "запущенный этим install.sh процесс (PID ${expected_pid} из run.pid). Скорее всего, " \
            "остался старый процесс со старым кодом (см. 'ps -p <PID> -o lstart,cmd'), который " \
            "не был корректно остановлен. Останавливать посторонний процесс автоматически не " \
            "буду — проверьте и завершите его вручную (kill -9 <PID>), затем запустите install.sh снова."
    fi
    log "Проверка PID пройдена: порт ${APP_PORT} слушает именно запущенный процесс (PID ${expected_pid})."
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
    ensure_repo_up_to_date
    ensure_python
    ensure_docker
    ensure_project_structure
    ensure_venv
    stop_existing_instance
    clear_python_bytecode_cache
    start_application

    if ! wait_for_healthcheck; then
        log "Сервис не ответил корректно. Последние строки лога:"
        tail -n 50 "${APP_LOG}" >&2 || true
        fail "Проверка HTTP 200 на ${HEALTHCHECK_URL} не пройдена. Установка прервана."
    fi

    verify_started_process_owns_port
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
