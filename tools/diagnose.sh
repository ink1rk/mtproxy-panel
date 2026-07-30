#!/usr/bin/env bash
#
# diagnose.sh — комплексная диагностика в один прогон.
# Собирает всё, что нужно для диагностики WireGuard/VLESS одним разом:
# состояние контейнеров, firewall, локальные self-тесты портов,
# и синхронный захват трафика (tcpdump) на обоих портах одновременно,
# пока ты подключаешься с телефона.
#
# Запуск: sudo bash tools/diagnose.sh
# (или просто bash tools/diagnose.sh, если уже под root)
#
# ВАЖНО: перед запуском убедись, что телефон под рукой — на десятом
# шаге скрипт даст 3 секунды и затем 30 секунд на захват трафика,
# именно в этот момент нужно подключаться к WireGuard и/или VLESS.

set -uo pipefail

CAPTURE_WINDOW_SECONDS=30
VLESS_PORT="${VLESS_PORT:-8443}"
WG_PORT="${WG_PORT:-51820}"

sep() {
    printf '\n================================================================\n'
    printf ' %s\n' "$1"
    printf '================================================================\n'
}

run() {
    # Выполняет команду, не прерывая скрипт при ошибке (несколько шагов
    # опциональны и могут отсутствовать в системе — это ожидаемо).
    "$@" 2>&1 || echo "(команда завершилась с ошибкой или недоступна — пропускаю)"
}

sep "0. Дата/время запуска диагностики"
date -u

sep "1. Docker-контейнеры (все, включая остановленные)"
run docker ps -a

sep "2. Статус systemd-сервиса панели"
run systemctl status mtproxy-panel --no-pager

sep "3. Определение хостинг-провайдера (best-effort, по метаданным облака)"
{
    result="$(timeout 2 curl -sf -H "Metadata-Flavor: Google" \
        http://169.254.169.254/computeMetadata/v1/instance/id 2>/dev/null)"
    [[ -n "${result}" ]] && echo "instance id: ${result} <- похоже на Google Cloud"

    result="$(timeout 2 curl -sf http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)"
    [[ -n "${result}" ]] && echo "instance id: ${result} <- похоже на AWS"

    result="$(timeout 2 curl -sf -H "Metadata: true" \
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null)"
    [[ -n "${result}" ]] && echo "metadata: ${result} <- похоже на Azure"

    result="$(timeout 2 curl -sf http://169.254.169.254/metadata/v1/id 2>/dev/null)"
    [[ -n "${result}" ]] && echo "droplet id: ${result} <- похоже на DigitalOcean"

    result="$(timeout 2 curl -sf -H "Metadata: true" \
        http://169.254.169.254/hetzner/v1/metadata 2>/dev/null)"
    [[ -n "${result}" ]] && echo "metadata: ${result} <- похоже на Hetzner"

    echo "(если выше ничего не появилось — метаданные недоступны, провайдер не определён автоматически; посмотри в письме от провайдера или в его личном кабинете)"
} 2>&1

sep "4. ufw (firewall уровня ОС)"
run ufw status verbose

sep "5. iptables — filter таблица"
run iptables -L -n -v
sep "5b. iptables — nat таблица"
run iptables -t nat -L -n -v

sep "6. Какие порты реально слушает хост"
run ss -tlnp
echo "--- UDP ---"
run ss -ulnp

sep "7. Локальный self-test VLESS: TLS-рукопожатие на 127.0.0.1:${VLESS_PORT}"
echo "(это НЕ полноценное REALITY-подключение — просто проверка, что порт вообще отвечает на TLS локально)"
run bash -c "timeout 5 openssl s_client -connect 127.0.0.1:${VLESS_PORT} -servername www.cloudflare.com </dev/null 2>&1 | head -25"

sep "8. WireGuard: текущее состояние интерфейса (ДО теста)"
run docker exec wg_server wg show

sep "9. Xray: текущий config.json на сервере"
run docker exec xray_server cat /etc/xray/config.json

sep "10. ЗАХВАТ ТРАФИКА — ${CAPTURE_WINDOW_SECONDS} секунд"
echo ""
echo ">>> ПРЯМО СЕЙЧАС возьми телефон и подключись:"
echo ">>> 1) к WireGuard (актуальный .conf/QR из панели)"
echo ">>> 2) к VLESS (актуальная vless:// ссылка/QR из панели)"
echo ">>> Начинаю захват через 3 секунды..."
sleep 3
run timeout "${CAPTURE_WINDOW_SECONDS}" tcpdump -i any -n "(udp port ${WG_PORT}) or (tcp port ${VLESS_PORT})" -c 200

sep "11. WireGuard: состояние СРАЗУ ПОСЛЕ теста (появилось ли рукопожатие?)"
run docker exec wg_server wg show

sep "12. Xray: свежие логи за последние 40 секунд (появились ли попытки?)"
run docker logs xray_server --tail 30 --since 40s

sep "ГОТОВО"
echo "Скопируй весь вывод этого скрипта целиком (от '=== 0. ===' до этой строки) и пришли."
