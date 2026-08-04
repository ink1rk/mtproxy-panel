# MTProxy + WireGuard + VLESS Control Panel

Production self-hosted VPN management panel on FastAPI.

| Сервис | Runtime | Управление |
|--------|---------|------------|
| **WireGuard** | native `wireguard-tools` | systemd `wg-quick@wg0`, конфиг `/etc/wireguard/wg0.conf` |
| **VLESS + REALITY** | native Xray binary | systemd `xray.service`, `/usr/local/etc/xray/config.json` |
| **MTProxy** | Docker | один контейнер на прокси |
| **Firewall / NAT** | nftables | таблица `inet mtproxy-panel` |

UI и FastAPI API сохранены; Docker для WireGuard/Xray **удалён** (bridge NAT
давал handshake 1–3 KiB без интернета).

## Возможности

### Прокси (MTProxy)
- Создание кнопкой (образ `telegrammessenger/proxy`)
- Secret: `classic` / `dd` / `ee` (fake-TLS)
- Ссылки tg:// / https:// и QR

### WireGuard VPN
- Native `wg-quick@wg0` + автоматический nftables MASQUERADE
- Клиент = только имя → ключи, IP, `.conf`, QR
- Горячее применение peer-ов через `wg syncconf`
- После setup: health-check (service / port / routing / egress)

### VLESS (Xray + REALITY + Vision)
- Native Xray + systemd
- Клиент = имя → UUID, `vless://`, QR
- `minClientVer=1.0.0` (совместимость с мобильными клиентами)
- После setup: те же health-check'и

### Логи
- `/logs` — app.log + journalctl (WG/Xray) + Docker MTProxy

## Архитектура

```
main.py                 # FastAPI + автозапуск native VPN
vpn_service.py          # оркестрация WG/Xray + health
wireguard_manager.py    # wg-quick / wg syncconf / systemd
xray_manager.py         # xray binary + systemd
firewall_manager.py     # nftables NAT + ports
vpn_health.py           # обязательные проверки после setup
host_exec.py            # привилегированные host-команды
mtproxy.py              # Docker MTProxy (без изменений по смыслу)
docker_manager.py       # Docker SDK только для MTProxy
install.sh              # python + docker(MTProxy) + wireguard + xray + nftables
```

## Порты

| Сервис        | Протокол | По умолчанию |
|---------------|----------|--------------|
| Панель        | TCP      | 8000         |
| WireGuard     | UDP      | 51820        |
| VLESS         | TCP      | 8443         |
| MTProxy       | TCP      | случайный    |

В **облачном firewall** (Timeweb / Hetzner / …) откройте `51820/udp`,
`8443/tcp`, `8000/tcp` и порты MTProxy.

## Установка

```bash
git clone https://github.com/ink1rk/mtproxy-panel.git
cd mtproxy-panel
bash install.sh
```

`install.sh` делает чистую установку:

1. Python 3.10+ venv + зависимости  
2. Docker (только для MTProxy) + pull `telegrammessenger/proxy`  
3. Удаляет legacy контейнеры `wg_server` / `xray_server`  
4. `wireguard-tools`, `nftables`, `ip_forward`  
5. Xray-core (`/usr/local/bin/xray`)  
6. systemd-юнит панели **от root** (нужен для wg/nft/xray)  
7. Базовая nftables-таблица + ufw allow при активном ufw  

### Миграция со старого Docker-WG/Xray

```bash
git fetch origin
git checkout cursor/native-vpn-stack-3616   # или main после merge
bash install.sh
# В панели: WireGuard → Сброс → Настроить заново → новый QR на телефон
# То же для VLESS (не поднимайте оба сразу, пока тестируете)
```

### Диагностика

```bash
bash tools/quick_check.sh
bash tools/diagnose.sh
systemctl status wg-quick@wg0
systemctl status xray
wg show
nft list table inet mtproxy-panel
```

После handshake у WireGuard **transfer должен расти** (KiB→MiB). Если снова
1–3 KiB — смотрите облачный firewall / nftables masquerade / `ip_forward`.

## Технические детали

**WireGuard**: Curve25519 keys. Конфиг в `/etc/wireguard/wg0.conf` без PostUp —
NAT делает nftables (`masquerade` для VPN-подсети, `oifname != wg0`).
Клиентский MTU = 1280.

**VLESS + REALITY**: Vision (`xtls-rprx-vision`), dest по умолчанию
`www.cloudflare.com:443`. Список клиентов — перезапись config.json +
`systemctl restart xray`.

**MTProxy**: без изменений, Docker bridge + published TCP ports.

## Безопасность

- Ключи через `secrets` / `cryptography`
- Пароль админа: PBKDF2-HMAC-SHA256
- `/etc/wireguard/*.conf` mode 0600
- Панель на `:8000` без TLS — ограничьте доступ (SSH-туннель / firewall)
