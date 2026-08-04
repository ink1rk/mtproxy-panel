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
# Верхняя поддерживаемая минорная версия. Ubuntu 26.04 (resolute) уже
# поставляет python3=3.14 и НЕ имеет пакетов python3.12/3.13 — поэтому
# 3.14 обязан быть first-class (requirements.txt содержит версии с cp314 wheels).
readonly PYTHON_MAX_MINOR=14
readonly SYSTEMD_SERVICE_NAME="mtproxy-panel"
readonly SYSTEMD_UNIT_FILE="/etc/systemd/system/${SYSTEMD_SERVICE_NAME}.service"

# Выбирается в ensure_python(); дальше venv создаётся именно им.
PYTHON_BIN="python3"

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

has_systemd() {
    [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1
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
# 1. Установка / выбор подходящего Python
# ---------------------------------------------------------------------------
_python_version_of() {
    # Печатает "major.minor" для переданного интерпретатора, либо пусто.
    local bin="$1"
    command -v "${bin}" >/dev/null 2>&1 || return 1
    "${bin}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null
}

_python_is_usable() {
    # Поддерживаем 3.10 … 3.14 включительно (3.14 = дефолт Ubuntu 26.04 resolute).
    local bin="$1"
    local version major minor
    version="$(_python_version_of "${bin}")" || return 1
    major="${version%%.*}"
    minor="${version##*.}"
    if (( major != PYTHON_MIN_MAJOR )); then
        return 1
    fi
    if (( minor < PYTHON_MIN_MINOR || minor > PYTHON_MAX_MINOR )); then
        return 1
    fi
    "${bin}" -m venv --help >/dev/null 2>&1 || return 1
    return 0
}

_apt_install_optional() {
    # Best-effort: отсутствие пакета (как python3.12 на Ubuntu resolute)
    # НЕ должно ронять install.sh при set -e.
    local pkg
    for pkg in "$@"; do
        if as_root apt-get install -y "${pkg}" >/dev/null 2>&1; then
            log "Установлен пакет '${pkg}'."
        else
            log "Пакет '${pkg}' недоступен в apt — пропускаю."
        fi
    done
}

_ensure_python_system_packages() {
    log "Проверяю системные пакеты Python / venv."
    as_root apt-get update -y

    # Обязательный минимум для текущей ОС (на resolute это python3=3.14).
    as_root apt-get install -y python3 python3-pip python3-venv

    # Опционально: версионные интерпретаторы (есть на 22.04/24.04, нет на 26.04)
    # и libs на случай, если pip всё же решит собрать что-то из исходников.
    _apt_install_optional \
        python3.14-venv \
        python3.13 \
        python3.13-venv \
        python3.12 \
        python3.12-venv \
        python3.11 \
        python3.11-venv \
        libjpeg-dev \
        zlib1g-dev

    # Если python3 есть, но без venv — дотягиваем версионный пакет под его minor.
    if command -v python3 >/dev/null 2>&1 && ! python3 -m venv --help >/dev/null 2>&1; then
        local minor
        minor="$(python3 -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || true)"
        if [[ -n "${minor}" ]]; then
            _apt_install_optional "python3.${minor}-venv"
        fi
        as_root apt-get install -y python3-venv || true
    fi
}

ensure_python() {
    local candidate

    # 1) Уже есть пригодный интерпретатор — берём лучший доступный.
    for candidate in python3.12 python3.13 python3.14 python3.11 python3; do
        if _python_is_usable "${candidate}"; then
            PYTHON_BIN="$(command -v "${candidate}")"
            log "Использую ${PYTHON_BIN} ($(_python_version_of "${PYTHON_BIN}")) для venv."
            return
        fi
    done

    # 2) Доустанавливаем системные пакеты (без падения на отсутствующих 3.12).
    _ensure_python_system_packages

    for candidate in python3.12 python3.13 python3.14 python3.11 python3; do
        if _python_is_usable "${candidate}"; then
            PYTHON_BIN="$(command -v "${candidate}")"
            log "Использую ${PYTHON_BIN} ($(_python_version_of "${PYTHON_BIN}")) для venv."
            return
        fi
    done

    local have_ver=""
    if command -v python3 >/dev/null 2>&1; then
        have_ver="$(_python_version_of python3 || echo '?')"
    fi
    fail "Не удалось найти пригодный Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}–${PYTHON_MIN_MAJOR}.${PYTHON_MAX_MINOR} с модулем venv (сейчас python3=${have_ver:-нет}). Установите: apt install -y python3 python3-venv && bash install.sh"
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

    # ВАЖНО: 'systemctl enable' вызываем ВСЕГДА, а не только когда daemon сейчас
    # неактивен — иначе на повторных запусках install.sh (когда Docker уже
    # запущен) автозапуск при перезагрузке сервера никогда бы не включился,
    # если по какой-то причине не был включён при самой первой установке.
    if has_systemd; then
        as_root systemctl enable docker >/dev/null 2>&1 || true
    fi
    if ! as_root systemctl is-active --quiet docker 2>/dev/null; then
        log "Запускаю Docker daemon."
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
# 2b. Предзагрузка Docker-образов панели
# ---------------------------------------------------------------------------
ensure_docker_images() {
    # Без локальных образов создание MTProxy/WG/Xray падает с непрозрачным
    # "500 Server Error .../images/create". Тянем их на этапе установки —
    # если registry недоступен, пользователь узнает сразу, а не из UI.
    local -a images=(
        "telegrammessenger/proxy:latest"
        "teddysun/xray:latest"
        "lscr.io/linuxserver/wireguard:latest"
    )
    local image
    for image in "${images[@]}"; do
        log "Проверяю Docker-образ '${image}'…"
        if as_root docker image inspect "${image}" >/dev/null 2>&1; then
            log "Образ '${image}' уже есть локально."
            continue
        fi
        log "Скачиваю '${image}' (это может занять несколько минут)…"
        if ! as_root docker pull "${image}"; then
            fail "Не удалось скачать образ '${image}'. Обычно это сеть/DNS/Docker Hub rate limit. Проверьте: docker pull ${image}. При блокировке Hub настройте registry-mirror в /etc/docker/daemon.json и перезапустите docker."
        fi
    done
    log "Все необходимые Docker-образы доступны локально."
}

# ---------------------------------------------------------------------------
# 3. Создание структуры проекта (директории создаются и в config.py,
#    но гарантируем их наличие до старта, чтобы установка была явной)
# ---------------------------------------------------------------------------
ensure_project_structure() {
    log "Создаю структуру каталогов проекта."
    mkdir -p "${SCRIPT_DIR}/data" \
             "${SCRIPT_DIR}/data/wireguard/wg_confs" \
             "${SCRIPT_DIR}/data/xray" \
             "${SCRIPT_DIR}/logs" \
             "${SCRIPT_DIR}/static/qr" \
             "${SCRIPT_DIR}/templates"
}

# ---------------------------------------------------------------------------
# 4. Виртуальное окружение и зависимости
# ---------------------------------------------------------------------------
ensure_venv() {
    local recreate=0
    local venv_version=""
    local wanted_version

    wanted_version="$(_python_version_of "${PYTHON_BIN}")"

    if [[ -d "${VENV_DIR}" && -x "${VENV_DIR}/bin/python" ]]; then
        venv_version="$(_python_version_of "${VENV_DIR}/bin/python" || echo "")"
        if [[ -z "${venv_version}" || "${venv_version}" != "${wanted_version}" ]]; then
            log "Существующий venv на Python ${venv_version:-?} не совпадает с ${PYTHON_BIN} (${wanted_version}) — пересоздаю."
            recreate=1
        elif ! "${VENV_DIR}/bin/python" -c "import fastapi, pydantic, PIL, docker" >/dev/null 2>&1; then
            log "Venv на Python ${venv_version} без рабочих зависимостей — пересоздаю."
            recreate=1
        fi
    else
        recreate=1
    fi

    if (( recreate == 1 )); then
        if [[ -d "${VENV_DIR}" ]]; then
            log "Удаляю старое виртуальное окружение."
            rm -rf "${VENV_DIR}"
        fi
        log "Создаю виртуальное окружение через ${PYTHON_BIN} (${wanted_version})."
        "${PYTHON_BIN}" -m venv "${VENV_DIR}"
    else
        log "Виртуальное окружение уже существует (Python ${venv_version})."
    fi

    log "Устанавливаю зависимости из requirements.txt (готовые wheels для native-пакетов)."
    "${VENV_DIR}/bin/pip" install --upgrade pip --quiet
    # Для native-пакетов запрещаем сборку из исходников: на 3.14 отсутствие
    # wheel раньше превращалось в 200 строк ошибок компиляции jpeg/rust.
    if ! "${VENV_DIR}/bin/pip" install \
            --only-binary=pillow,pydantic-core,cryptography \
            -r "${SCRIPT_DIR}/requirements.txt"; then
        fail "Не удалось установить Python-зависимости для Python ${wanted_version}. Обновите ветку/requirements.txt, затем: rm -rf venv && bash install.sh"
    fi

    "${VENV_DIR}/bin/python" -c "import fastapi, pydantic, PIL, docker, qrcode, cryptography; print('deps OK')"
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

systemd_managed_pid() {
    [[ -f "${SYSTEMD_UNIT_FILE}" ]] || return 0
    as_root systemctl show -p MainPID --value "${SYSTEMD_SERVICE_NAME}" 2>/dev/null || true
}

stop_existing_instance() {
    local under_systemd=0
    if has_systemd && [[ -f "${SYSTEMD_UNIT_FILE}" ]] \
        && as_root systemctl is-active --quiet "${SYSTEMD_SERVICE_NAME}" 2>/dev/null; then
        under_systemd=1
        log "Приложение уже управляется systemd-юнитом '${SYSTEMD_SERVICE_NAME}' — " \
            "он будет корректно перезапущен ниже через 'systemctl restart'."
    fi

    if [[ "${under_systemd}" -eq 0 && -f "${PID_FILE}" ]]; then
        local old_pid
        old_pid="$(cat "${PID_FILE}")"
        if kill -0 "${old_pid}" 2>/dev/null; then
            log "Останавливаю ранее запущенный экземпляр приложения (PID ${old_pid})."
            kill "${old_pid}" || true
            wait_for_pid_exit "${old_pid}" 10
        fi
        rm -f "${PID_FILE}"
    fi

    # ВАЖНО: PID_FILE (или сам systemd-юнит) может рассинхронизироваться с
    # реальностью (сбой между запусками, переиспользование номера PID, ручной
    # запуск мимо install.sh/systemd и т.п.) — тогда обычный kill/restart
    # никого не остановит, порт останется занят "забытым" процессом со старым
    # кодом, а health-check ниже всё равно получит HTTP 200 от него и
    # install.sh решит, что всё в порядке. Поэтому независимо от PID_FILE
    # явно проверяем, кто слушает APP_PORT, и добиваем таких "зомби" —
    # кроме процесса, который сейчас легитимно управляется systemd (его
    # трогать не нужно, 'systemctl restart' сделает это сам).
    local managed_pid=""
    if [[ "${under_systemd}" -eq 1 ]]; then
        managed_pid="$(systemd_managed_pid)"
    fi

    local stale_pids
    stale_pids="$(find_pids_on_app_port "${APP_PORT}")"
    if [[ -n "${managed_pid}" && "${managed_pid}" != "0" ]]; then
        stale_pids="$(grep -vx "${managed_pid}" <<< "${stale_pids}" || true)"
    fi

    if [[ -n "${stale_pids}" ]]; then
        log "Порт ${APP_PORT} всё ещё занят процессом(ами) [${stale_pids//$'\n'/, }], не учтённым(и) в run.pid/systemd — останавливаю."
        local pid
        for pid in ${stale_pids}; do
            as_root kill "${pid}" 2>/dev/null || true
        done
        sleep 2
        stale_pids="$(find_pids_on_app_port "${APP_PORT}")"
        if [[ -n "${managed_pid}" && "${managed_pid}" != "0" ]]; then
            stale_pids="$(grep -vx "${managed_pid}" <<< "${stale_pids}" || true)"
        fi
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

install_systemd_unit() {
    log "Устанавливаю systemd-юнит '${SYSTEMD_SERVICE_NAME}' (автозапуск при загрузке сервера, автоперезапуск при сбое)."
    local unit_content
    unit_content="$(cat <<EOF
[Unit]
Description=MTProxy Control Panel (FastAPI + uvicorn)
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${VENV_DIR}/bin/uvicorn main:app --host ${APP_HOST} --port ${APP_PORT}
Restart=on-failure
RestartSec=3
StandardOutput=append:${APP_LOG}
StandardError=append:${APP_LOG}

[Install]
WantedBy=multi-user.target
EOF
)"
    printf '%s\n' "${unit_content}" | as_root tee "${SYSTEMD_UNIT_FILE}" >/dev/null
    as_root systemctl daemon-reload
    as_root systemctl enable "${SYSTEMD_SERVICE_NAME}" >/dev/null 2>&1 || true
}

start_application() {
    if has_systemd; then
        install_systemd_unit
        log "Перезапускаю приложение через systemd (${SYSTEMD_SERVICE_NAME})."
        as_root systemctl restart "${SYSTEMD_SERVICE_NAME}"
        sleep 1

        local pid
        pid="$(systemd_managed_pid)"
        if [[ -n "${pid}" && "${pid}" != "0" ]]; then
            echo "${pid}" > "${PID_FILE}"
        else
            rm -f "${PID_FILE}"
        fi
        log "Приложение запущено через systemd, PID=${pid:-неизвестен}, логи: ${APP_LOG}"
        return
    fi

    log "systemd не обнаружен — запускаю приложение в фоне через nohup " \
        "(ВНИМАНИЕ: без systemd панель не переживёт перезагрузку сервера — " \
        "после ребута потребуется вручную запустить 'bash install.sh' снова)."
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
# 7. WireGuard: проверка поддержки ядром (best-effort, не фатально —
#    контейнер WireGuard-сервера сам умеет подгрузить модуль благодаря
#    capability SYS_MODULE, если ядро поддерживает WireGuard).
# ---------------------------------------------------------------------------
ensure_wireguard_kernel_support() {
    if as_root modprobe wireguard 2>/dev/null; then
        log "Модуль ядра WireGuard доступен."
    elif [[ -d /sys/module/wireguard ]]; then
        log "Модуль ядра WireGuard уже загружен."
    else
        log "ВНИМАНИЕ: не удалось подтвердить поддержку WireGuard ядром хоста. " \
            "Обычно это не проблема на Ubuntu Server (ядро >= 5.6 включает WireGuard " \
            "изначально) — контейнер WireGuard-сервера попробует загрузить модуль сам " \
            "при первом запуске из панели."
    fi
}

# ---------------------------------------------------------------------------
# 8. Firewall: при активном ufw открываем порты панели и VPN по умолчанию.
#    Docker обычно пробивает свои -p через iptables сам, но на части Ubuntu
#    (и при ufw-docker конфликтах) без явного allow клиенты с телефона
#    просто не достучатся — снаружи «ничего не открывается».
# ---------------------------------------------------------------------------
ensure_firewall_allows_panel() {
    if ! command -v ufw >/dev/null 2>&1; then
        return
    fi
    if ! as_root ufw status 2>/dev/null | grep -qi "Status: active"; then
        return
    fi
    log "Обнаружен активный ufw — открываю порты панели и VPN по умолчанию."
    as_root ufw allow "${APP_PORT}/tcp" >/dev/null 2>&1 || true
    as_root ufw allow 51820/udp >/dev/null 2>&1 || true   # WireGuard
    as_root ufw allow 8443/tcp >/dev/null 2>&1 || true    # VLESS+REALITY
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
    require_root_or_sudo
    ensure_repo_up_to_date
    ensure_python
    ensure_docker
    ensure_docker_images
    ensure_wireguard_kernel_support
    ensure_firewall_allows_panel
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
    if has_systemd; then
        log " Панель установлена как systemd-сервис '${SYSTEMD_SERVICE_NAME}' и будет"
        log " автоматически запускаться при перезагрузке сервера, а также сама"
        log " перезапускаться при сбое."
        log " Статус:          systemctl status ${SYSTEMD_SERVICE_NAME}"
        log " Логи (journal):  journalctl -u ${SYSTEMD_SERVICE_NAME} -f"
        log " Перезапуск:      systemctl restart ${SYSTEMD_SERVICE_NAME}"
        log " Остановить:      systemctl stop ${SYSTEMD_SERVICE_NAME}"
    else
        log " ВНИМАНИЕ: systemd не найден, панель запущена в фоне без автозапуска —"
        log " после перезагрузки сервера потребуется вручную выполнить 'bash install.sh'."
        log " PID процесса:    $(cat "${PID_FILE}" 2>/dev/null || echo '?')"
        log " Остановить:      kill \$(cat ${PID_FILE})"
    fi
    log "==============================================================="
}

main "$@"
