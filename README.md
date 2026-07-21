# MTProxy Control Panel

Веб-панель управления Telegram MTProxy на FastAPI + Docker SDK.
Позволяет создавать, просматривать и удалять MTProxy-контейнеры
через браузер, без ручного редактирования конфигов.

## Возможности

- Создание MTProxy одной кнопкой (официальный образ `telegrammessenger/proxy`)
- Список всех прокси: статус контейнера, IP, порт, secret, дата создания
- Ссылки `tg://proxy?...` и `https://t.me/proxy?...`
- QR-код для быстрого подключения
- Удаление с подтверждением (контейнер, QR и запись в БД удаляются полностью)
- Полный откат при любой ошибке создания — "полуготовых" прокси не остаётся

## Стек

Python 3.12, FastAPI, Jinja2, SQLite, Docker SDK, Bootstrap, qrcode, Pillow, uvicorn.
Без docker-compose, systemd, redis, celery, nginx, ssl-терминации и JS-фреймворков.

## Архитектура

```
main.py            # точка входа FastAPI, логирование, lifespan
routes.py           # HTTP-роуты (только вызовы service.py)
service.py          # сервисный слой: бизнес-логика создания/удаления
mtproxy.py          # оркестрация провижининга контейнера + rollback
docker_manager.py   # обёртка над Docker SDK
repository.py       # Repository Pattern поверх SQLite
database.py         # соединение с SQLite, создание таблиц, авто-миграция
models.py           # доменная модель Proxy
schemas.py          # Pydantic v2 схемы
utils.py            # порты, secret, QR, публичный IP
config.py           # все настройки в одном месте
templates/index.html
static/qr/          # сгенерированные QR-коды
logs/                # логи с ротацией (RotatingFileHandler)
```

## Установка на Ubuntu Server

```bash
git clone <URL_ТВОЕГО_РЕПОЗИТОРИЯ>.git
cd mtproxy-panel
bash install.sh
```

Скрипт автоматически:

1. установит Python 3 и Docker, если их нет;
2. создаст `venv` и поставит зависимости;
3. создаст структуру каталогов и SQLite-базу;
4. запустит FastAPI в фоне (`nohup ... &`, без systemd);
5. подождёт запуск и проверит `curl http://127.0.0.1:8000/` -> HTTP 200 + HTML;
6. проверит `docker ps`;
7. если что-то не так — завершится с ошибкой и покажет последние строки лога.

После успешной установки открой в браузере:

```
http://<IP_СЕРВЕРА>:8000/
```

### Остановка / перезапуск

```bash
kill $(cat run.pid)      # остановить
bash install.sh          # перезапустить (сам остановит старый процесс)
```

### Логи

```bash
tail -f logs/uvicorn.log   # логи процесса uvicorn
tail -f logs/app.log       # логи приложения (RotatingFileHandler)
```

## Как выложить проект на свой GitHub

Я не могу запушить код в твой аккаунт — вот три команды, которые сделают это сам:

```bash
cd mtproxy-panel
git init
git add .
git commit -m "MTProxy Control Panel: initial production-ready version"
git branch -M main
git remote add origin https://github.com/<твой_логин>/<имя_репозитория>.git
git push -u origin main
```

После этого установка на любом Ubuntu-сервере — это всего две команды:

```bash
git clone https://github.com/<твой_логин>/<имя_репозитория>.git
cd <имя_репозитория> && bash install.sh
```

## Примечания по безопасности

- Secret генерируется через `secrets.token_hex(16)`, не `random`, не `uuid`.
- Все входные данные, отображаемые в HTML, экранируются (`html.escape` / автоэкранирование Jinja2).
- Никаких `os.system` — только `subprocess`/Docker SDK с явными таймаутами.
- Панель по умолчанию слушает `0.0.0.0:8000` без TLS (SSL-терминация — вне
  скоупа этого проекта). Для доступа из интернета рекомендуется закрыть порт
  8000 файрволом и открывать доступ, например, через SSH-туннель, либо
  добавить TLS самостоятельно на внешнем уровне.
