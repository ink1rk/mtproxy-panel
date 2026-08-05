#!/usr/bin/env bash
#
# install.sh — production-установка MTProxy Control Panel на Ubuntu Server.
#
# Стек:
#   - FastAPI panel (systemd, root — нужен для wg/nft/xray)
#   - WireGuard: native wg-quick@wg0 (PostUp как wg-easy + DOCKER-USER)
#   - Xray: native binary + systemd xray.service
#   - MTProxy: Docker (один контейнер на прокси)
#   - Firewall: nftables input; WG-NAT через iptables PostUp
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
readonly SYSTEMD_SERVICE_NAME="mtproxy-panel"
readonly SYSTEMD_UNIT_FILE="/etc/systemd/system/${SYSTEMD_SERVICE_NAME}.service"

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

    # Универсальные пакеты обязательны. Версионные (python3.12-venv и т.п.)
    # на Ubuntu 26.04/resolute часто отсутствуют — ставим best-effort.
    as_root apt-get install -y python3 python3-venv python3-pip
    if [[ -n "${py_minor_pkg}" && "${py_minor_pkg}" != "python3." ]]; then
        as_root apt-get install -y "${py_minor_pkg}-venv" 2>/dev/null || true
        as_root apt-get install -y "${py_minor_pkg}-dev" 2>/dev/null || true
    fi

    if ! python3 -m venv --help >/dev/null 2>&1; then
        fail "Не удалось установить рабочий модуль venv для python3. Установите вручную: apt install python3-venv и запустите install.sh снова."
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

ensure_mtproxy_image() {
    local images=(
        "telegrammessenger/proxy:latest"
        "lscr.io/linuxserver/wireguard:latest"
    )
    local image
    for image in "${images[@]}"; do
        if as_root docker image inspect "${image}" >/dev/null 2>&1; then
            log "Docker-образ уже есть: ${image}"
            continue
        fi
        log "Скачиваю Docker-образ ${image}..."
        if ! as_root docker pull "${image}"; then
            fail "Не удалось скачать ${image}. Проверьте сеть/Docker Hub и повторите."
        fi
    done
}

remove_legacy_docker_vpn() {
    # WG и Xray больше не в Docker — убираем старые контейнеры.
    for name in wg_server xray_server; do
        if as_root docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "${name}"; then
            log "Удаляю legacy Docker-контейнер ${name}."
            as_root docker rm -f "${name}" >/dev/null 2>&1 || true
        fi
    done
}

# ---------------------------------------------------------------------------
# Native VPN stack: wireguard-tools, nftables, xray binary
# ---------------------------------------------------------------------------
ensure_vpn_stack() {
    log "Устанавливаю native VPN-стек (wireguard-tools, nftables, curl, unzip)."
    as_root apt-get update -y
    as_root apt-get install -y \
        wireguard wireguard-tools \
        nftables \
        curl ca-certificates unzip \
        iproute2 iptables
    as_root apt-get install -y openresolv 2>/dev/null \
        || as_root apt-get install -y resolvconf 2>/dev/null \
        || true

    if as_root modprobe wireguard 2>/dev/null; then
        log "Модуль ядра wireguard загружен."
    elif [[ -d /sys/module/wireguard ]]; then
        log "Модуль ядра wireguard уже активен."
    else
        log "ВНИМАНИЕ: modprobe wireguard не удался — проверьте ядро (>= 5.6)."
    fi

    as_root sysctl -w net.ipv4.ip_forward=1 >/dev/null
    printf 'net.ipv4.ip_forward=1\n' | as_root tee /etc/sysctl.d/99-mtproxy-panel-forward.conf >/dev/null

    as_root mkdir -p /etc/wireguard /usr/local/etc/xray /etc/nftables.d
    as_root chmod 700 /etc/wireguard

    # WireGuard — native wg-quick@wg0. Docker wg_server глушим.
    as_root docker rm -f wg_server >/dev/null 2>&1 || true
    if has_systemd; then
        as_root systemctl enable mtproxy-wg-forward.service >/dev/null 2>&1 || true
    fi

    relax_wg_apparmor
}

# ---------------------------------------------------------------------------
# AppArmor 'wg' / 'wg-quick' на Ubuntu 24.04+ мешает native WireGuard:
#   - профиль допускает exec только xtables-nft-multi (легаси iptables → deny)
#   - netlink-медиация иногда даёт RTNETLINK Permission denied на
#     `ip link set mtu` внутри wg-quick//ip суб-профиля
# Снимаем профили один раз при установке (идемпотентно). WireGuardManager
# на всякий случай повторяет то же самое перед каждым ensure_server_running.
# ---------------------------------------------------------------------------
relax_wg_apparmor() {
    if ! command -v apparmor_parser >/dev/null 2>&1; then
        return
    fi
    log "Снимаю AppArmor-профили wg/wg-quick (ломают native WireGuard на Ubuntu)."
    as_root mkdir -p /etc/apparmor.d/disable
    local profile
    for profile in wg wg-quick; do
        if [[ -f "/etc/apparmor.d/${profile}" ]] && [[ ! -e "/etc/apparmor.d/disable/${profile}" ]]; then
            as_root ln -sf "/etc/apparmor.d/${profile}" "/etc/apparmor.d/disable/${profile}"
        fi
        as_root apparmor_parser -R "/etc/apparmor.d/${profile}" >/dev/null 2>&1 || true
    done

    # nftables service + include наших правил
    if has_systemd; then
        as_root systemctl enable nftables >/dev/null 2>&1 || true
        as_root systemctl start nftables >/dev/null 2>&1 || true
    fi
    if [[ -f /etc/nftables.conf ]] && ! grep -q 'mtproxy-panel.nft' /etc/nftables.conf 2>/dev/null; then
        printf '\ninclude "/etc/nftables.d/mtproxy-panel.nft"\n' | as_root tee -a /etc/nftables.conf >/dev/null || true
    fi

    ensure_xray_binary
}

ensure_xray_binary() {
    if [[ -x /usr/local/bin/xray ]]; then
        log "Xray уже установлен: $(/usr/local/bin/xray version 2>/dev/null | head -1 || echo /usr/local/bin/xray)"
        return
    fi

    log "Устанавливаю Xray-core (официальный install-release.sh)..."
    local installer="/tmp/xray-install-release.sh"
    if ! curl -fsSL "https://github.com/XTLS/Xray-install/raw/main/install-release.sh" -o "${installer}"; then
        fail "Не удалось скачать Xray install-release.sh с GitHub."
    fi
    if ! as_root bash "${installer}" install; then
        fail "Установка Xray не удалась. Проверьте доступ к github.com."
    fi
    rm -f "${installer}"

    if [[ ! -x /usr/local/bin/xray ]]; then
        fail "После установки /usr/local/bin/xray не найден."
    fi
    # Останавливаем дефолтный unit до настройки из панели (пустой/чужой конфиг).
    if has_systemd; then
        as_root systemctl disable --now xray >/dev/null 2>&1 || true
    fi
    log "Xray установлен: $(/usr/local/bin/xray version 2>/dev/null | head -1)"
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
    log "Устанавливаю systemd-юнит '${SYSTEMD_SERVICE_NAME}' (root: wg-quick/nft/xray)."
    local unit_content
    unit_content="$(cat <<EOF
[Unit]
Description=MTProxy Control Panel (FastAPI + native WireGuard/Xray + Docker MTProxy)
After=network-online.target docker.service nftables.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${VENV_DIR}/bin/uvicorn main:app --host ${APP_HOST} --port ${APP_PORT}
Restart=on-failure
RestartSec=3
StandardOutput=append:${APP_LOG}
StandardError=append:${APP_LOG}
# Нужны для управления native VPN и Docker MTProxy
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_MODULE

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
# Firewall: ufw (если активен) + базовая nftables-таблица панели
# ---------------------------------------------------------------------------
ensure_firewall_allows_panel() {
    if command -v ufw >/dev/null 2>&1 \
        && as_root ufw status 2>/dev/null | grep -qi "Status: active"; then
        log "Обнаружен активный ufw — открываю порты панели и VPN."
        as_root ufw allow "${APP_PORT}/tcp" >/dev/null 2>&1 || true
        as_root ufw allow 443/udp >/dev/null 2>&1 || true
        as_root ufw allow 8443/tcp >/dev/null 2>&1 || true
    fi

    # Базовая nftables-таблица (панель). WG/Xray порты допишет панель при setup.
    if command -v nft >/dev/null 2>&1; then
        local rules
        rules="$(cat <<EOF
table inet mtproxy-panel {
  chain input {
    type filter hook input priority filter; policy accept;
    tcp dport ${APP_PORT} accept comment "mtproxy-panel"
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
  }
}
EOF
)"
        as_root nft delete table inet mtproxy-panel >/dev/null 2>&1 || true
        printf '%s\n' "${rules}" | as_root nft -f -
        printf '%s\n' "${rules}" | as_root tee /etc/nftables.d/mtproxy-panel.nft >/dev/null
        log "nftables таблица mtproxy-panel применена."
    fi

    # Docker ставит FORWARD DROP — сразу ставим ACCEPT для wg0.
    install_wg_forward_helper
    as_root bash "${SCRIPT_DIR}/tools/fix_wg_forward.sh" || true
}

install_wg_forward_helper() {
    # После рестарта Docker DOCKER-USER очищается — поднимаем правила снова.
    # Панель при первом ensure_ready() пишет /usr/local/sbin/mtproxy-wg-nat.sh
    # с уже подставленными реальными subnet/port/wan — предпочитаем его;
    # пока панель ещё не стартовала (самый первый install), используем
    # generic tools/fix_wg_forward.sh с дефолтами (443/10.8.0.0/24).
    local unit_path="/etc/systemd/system/mtproxy-wg-forward.service"
    local unit_content
    unit_content="$(cat <<EOF
[Unit]
Description=Allow WireGuard forwarding past Docker iptables DROP
After=network-online.target docker.service nftables.service
Wants=network-online.target
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '/usr/local/sbin/mtproxy-wg-nat.sh 2>/dev/null || ${SCRIPT_DIR}/tools/fix_wg_forward.sh'
ExecStartPost=/bin/true

[Install]
WantedBy=multi-user.target docker.service
EOF
)"
    if has_systemd; then
        printf '%s\n' "${unit_content}" | as_root tee "${unit_path}" >/dev/null
        as_root systemctl daemon-reload
        as_root systemctl enable mtproxy-wg-forward.service >/dev/null 2>&1 || true
        as_root systemctl start mtproxy-wg-forward.service >/dev/null 2>&1 || true
        log "Установлен systemd helper mtproxy-wg-forward.service (Docker FORWARD bypass)."
    fi
}

verify_vpn_binaries() {
    local missing=()
    command -v docker >/dev/null 2>&1 || missing+=("docker")
    command -v nft >/dev/null 2>&1 || missing+=("nft")
    [[ -x /usr/local/bin/xray ]] || missing+=("xray")
    if (( ${#missing[@]} > 0 )); then
        fail "Не найдены компоненты VPN-стека: ${missing[*]}"
    fi
    log "Проверка VPN-стека пройдена (docker, nft, xray)."
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
    require_root_or_sudo
    ensure_repo_up_to_date
    ensure_python
    ensure_docker
    ensure_mtproxy_image
    remove_legacy_docker_vpn
    ensure_vpn_stack
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
    verify_vpn_binaries

    log "==============================================================="
    log " MTProxy Control Panel (native VPN stack) установлена."
    log " Откройте в браузере: http://<IP_ЭТОГО_СЕРВЕРА>:${APP_PORT}/"
    log " WireGuard: native wg-quick@wg0 (PostUp как wg-easy)"
    log " VLESS:     systemd xray.service"
    log " MTProxy:   Docker (telegrammessenger/proxy)"
    if grep -q "СОЗДАНА ПЕРВАЯ УЧЁТНАЯ ЗАПИСЬ" "${APP_LOG}" 2>/dev/null; then
        log " Учётные данные администратора (показываются один раз):"
        grep -A 3 "Логин:" "${APP_LOG}" | tail -n 3 | sed 's/^/   /'
    else
        log " Учётная запись администратора уже существует (пароль не менялся)."
    fi
    log " Логи приложения: ${APP_LOG}"
    if has_systemd; then
        log " Статус панели:   systemctl status ${SYSTEMD_SERVICE_NAME}"
        log " Логи панели:     journalctl -u ${SYSTEMD_SERVICE_NAME} -f"
        log " WireGuard:       docker exec wg_server wg show"
        log " Xray:            systemctl status xray"
        log " Перезапуск:      systemctl restart ${SYSTEMD_SERVICE_NAME}"
    else
        log " ВНИМАНИЕ: systemd не найден — native VPN требует systemd."
        log " PID процесса:    $(cat "${PID_FILE}" 2>/dev/null || echo '?')"
    fi
    log " Облачный firewall: откройте 443/udp (WireGuard), 8443/tcp (VLESS), ${APP_PORT}/tcp (панель)"
    log "==============================================================="
}

main "$@"
