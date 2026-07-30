#!/usr/bin/env bash
#
# diagnose_vless.sh — прицельная диагностика ТОЛЬКО VLESS-порта,
# с полным содержимым пакетов (не только заголовками), чтобы увидеть,
# приходит ли на сервер валидный TLS ClientHello или повреждённые байты.
#
# Запуск: sudo bash tools/diagnose_vless.sh
#
# В отличие от tools/diagnose.sh (общая диагностика), этот скрипт:
# - слушает ТОЛЬКО TCP-порт VLESS (без шума от WireGuard/других портов);
# - пишет полный pcap-файл без обрезки пакетов (-s 0, без лимита -c);
# - затем распечатывает содержимое пакетов в hex+ASCII, чтобы можно было
#   увидеть, начинается ли полезная нагрузка с байтов TLS ClientHello
#   (0x16 0x03 0x01/0x03 — стандартная сигнатура начала TLS-рукопожатия).

set -uo pipefail

VLESS_PORT="${VLESS_PORT:-8443}"
CAPTURE_WINDOW_SECONDS="${CAPTURE_WINDOW_SECONDS:-40}"
PCAP_FILE="/tmp/vless_diag_$(date +%s).pcap"

sep() {
    printf '\n================================================================\n'
    printf ' %s\n' "$1"
    printf '================================================================\n'
}

sep "0. Дата/время запуска"
date -u

sep "1. Текущий config.json Xray (для справки)"
docker exec xray_server cat /etc/xray/config.json 2>&1 || echo "(не удалось прочитать)"

sep "2. ЗАХВАТ — ${CAPTURE_WINDOW_SECONDS} секунд, ТОЛЬКО порт ${VLESS_PORT}, без обрезки пакетов"
echo ""
echo ">>> ПРЯМО СЕЙЧАС подключись с телефона ТОЛЬКО к VLESS (WireGuard в этот раз не трогай,"
echo ">>> чтобы не засорять захват)."
echo ">>> Начинаю захват через 3 секунды..."
sleep 3
timeout "${CAPTURE_WINDOW_SECONDS}" tcpdump -i any -s 0 -w "${PCAP_FILE}" "tcp port ${VLESS_PORT}" 2>&1
echo "Захват завершён, файл: ${PCAP_FILE}"

sep "3. Свежие логи Xray сразу после теста"
docker logs xray_server --tail 30 --since "${CAPTURE_WINDOW_SECONDS}s" 2>&1

sep "4. Список TCP-пакетов в захвате (кратко, без содержимого)"
tcpdump -r "${PCAP_FILE}" -n 2>/dev/null | head -80

sep "5. Полное содержимое пакетов С ДАННЫМИ (hex+ASCII) — первые 40 таких пакетов"
echo "(ищем, начинается ли полезная нагрузка с 16 03 xx — это сигнатура начала TLS ClientHello)"
tcpdump -r "${PCAP_FILE}" -n -X 2>/dev/null | awk '
    /length [1-9]/ { show=1; count++; if (count > 40) exit }
    show { print }
    /^$/ { show=0 }
'

sep "6. Путь к сохранённому pcap-файлу (на случай, если нужно будет прислать целиком)"
echo "${PCAP_FILE}"
ls -la "${PCAP_FILE}"

sep "ГОТОВО"
echo "Скопируй весь вывод (особенно раздел 5 — hex+ASCII) и пришли."
