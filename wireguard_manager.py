"""
Docker-слой для WireGuard VPN сервера.

В отличие от MTProxy (где каждый прокси — отдельный контейнер), WireGuard
работает как ОДИН постоянный контейнер-сервер, обслуживающий множество
peer-ов через один и тот же UDP-порт. Peer-ы добавляются/удаляются
"горячо" через `wg syncconf` — без перезапуска контейнера и без разрыва
соединений остальных клиентов.

Образ: lscr.io/linuxserver/wireguard БЕЗ переменной окружения PEERS —
это официально документированный "bare/client mode": образ НЕ генерирует
peer-конфиги самостоятельно, а просто поднимает интерфейс из готового
wg_confs/wg0.conf, который полностью формирует и обновляет наша панель.
(Важно: даже PEERS=0 — это НЕ то же самое, что отсутствие переменной —
см. подробный комментарий в ensure_server_running() ниже.)
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import docker
from docker.errors import APIError, NotFound
from docker.models.containers import Container
from docker.types import LogConfig

import config
from docker_utils import ensure_image, format_docker_api_error

logger = logging.getLogger(__name__)


class WireGuardDockerError(RuntimeError):
    """Ошибка при работе с Docker-контейнером WireGuard-сервера."""


def _docker_log_config() -> LogConfig:
    return LogConfig(
        type=LogConfig.types.JSON,
        config=config.DOCKER_LOG_CONFIG["config"],
    )


class WireGuardManager:
    """Управляет жизненным циклом единственного контейнера WireGuard-сервера."""

    def __init__(self) -> None:
        try:
            self._client = docker.from_env()
            self._client.ping()
        except Exception as exc:
            raise WireGuardDockerError(
                "Docker daemon недоступен для управления WireGuard-сервером"
            ) from exc

    def _get_container(self) -> Container | None:
        try:
            return self._client.containers.get(config.WG_CONTAINER_NAME)
        except NotFound:
            return None

    def is_running(self) -> bool:
        container = self._get_container()
        if container is None:
            return False
        container.reload()
        return container.status == "running"

    def get_status(self) -> str:
        container = self._get_container()
        if container is None:
            return "missing"
        container.reload()
        return container.status

    def ensure_server_running(self, listen_port: int) -> None:
        """
        Создаёт (если не существует) и запускает контейнер WireGuard-сервера.
        Идемпотентно: если контейнер уже running — ничего не делает.
        Контейнеры в статусе exited/created после сорванного setup удаляются
        и создаются заново (иначе wg0 часто так и не поднимается).
        """
        container = self._get_container()
        if container is not None:
            container.reload()
            if container.status == "running":
                self.ensure_host_config_writable()
                return
            logger.warning(
                "Контейнер WireGuard в статусе '%s' — удаляю и создаю заново",
                container.status,
            )
            try:
                container.remove(force=True)
            except APIError as exc:
                raise WireGuardDockerError(
                    f"Не удалось удалить старый контейнер WireGuard: {format_docker_api_error(exc)}"
                ) from exc

        logger.info("Создаю контейнер WireGuard-сервера на порту %d/udp", listen_port)
        try:
            ensure_image(self._client, config.WG_DOCKER_IMAGE)
            # /dev/net/tun обязателен: без него wg-quick не создаёт wg0
            # («интерфейс не поднялся за Nс»), а страница setup в панели «висит».
            # SYS_MODULE не добавляем — на Timeweb/части VPS он подвешивает старт.
            run_kwargs: dict = {
                "image": config.WG_DOCKER_IMAGE,
                "name": config.WG_CONTAINER_NAME,
                "detach": True,
                "restart_policy": {"Name": "unless-stopped"},
                "cap_add": ["NET_ADMIN"],
                "sysctls": {
                    "net.ipv4.conf.all.src_valid_mark": "1",
                    "net.ipv4.ip_forward": "1",
                },
                "ports": {f"{listen_port}/udp": listen_port},
                # ВАЖНО: PEERS не задаём вовсе (а не "0"!).
                "environment": {"PUID": "0", "PGID": "0"},
                "volumes": {str(config.WG_CONFIG_DIR): {"bind": "/config", "mode": "rw"}},
                "log_config": _docker_log_config(),
            }
            # devices может быть недоступен в rootless docker — тогда пробуем без него,
            # а ниже форсим wg-quick up и отдадим понятную ошибку.
            try:
                container = self._client.containers.run(
                    **run_kwargs,
                    devices=["/dev/net/tun:/dev/net/tun"],
                )
            except APIError as tun_exc:
                logger.warning(
                    "Не удалось создать WG с /dev/net/tun (%s) — пробую без devices",
                    format_docker_api_error(tun_exc),
                )
                container = self._client.containers.run(**run_kwargs)
        except RuntimeError as exc:
            raise WireGuardDockerError(str(exc)) from exc
        except APIError as exc:
            raise WireGuardDockerError(
                f"Не удалось создать контейнер WireGuard: {format_docker_api_error(exc)}"
            ) from exc

        self._wait_running(container)
        self.ensure_host_config_writable()

    def ensure_host_config_writable(self) -> None:
        """
        linuxserver/wireguard после старта chown'ит /config на внутреннего
        пользователя образа — после этого процесс панели (даже если он
        создал файлы) может получить Permission denied при записи wg0.conf.
        Возвращаем a+rwX на смонтированную директорию через docker exec
        (нужен root внутри контейнера) и дублируем chmod на хосте.
        """
        container = self._get_container()
        if container is not None:
            try:
                container.reload()
                if container.status == "running":
                    container.exec_run(["chmod", "-R", "a+rwX", "/config"])
            except APIError as exc:
                logger.warning("Не удалось chmod /config внутри WireGuard-контейнера: %s", exc)

        root = Path(config.WG_CONFIG_DIR)
        try:
            if root.exists():
                os.chmod(root, 0o777)
                for path in root.rglob("*"):
                    try:
                        os.chmod(path, 0o777 if path.is_dir() else 0o666)
                    except OSError:
                        continue
        except OSError as exc:
            logger.warning("Не удалось chmod %s на хосте: %s", root, exc)

    def _wait_running(self, container: Container) -> None:
        deadline = time.monotonic() + config.DOCKER_WG_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            container.reload()
            if container.status == "running":
                return
            if container.status in {"exited", "dead"}:
                raise WireGuardDockerError(
                    f"Контейнер WireGuard завершился со статусом '{container.status}' при запуске"
                )
            time.sleep(0.5)
        raise WireGuardDockerError("Контейнер WireGuard не перешёл в статус 'running' за отведённое время")

    def reload_config(self) -> None:
        """
        Применяет обновлённый wg0.conf "на горячую" через `wg syncconf`,
        не разрывая существующие соединения других peer-ов.
        """
        container = self._get_container()
        if container is None:
            raise WireGuardDockerError("Контейнер WireGuard не найден — сервер ещё не настроен")

        exit_code, output = container.exec_run(
            [
                "bash", "-c",
                f"wg syncconf {config.WG_INTERFACE_NAME} "
                f"<(wg-quick strip /config/wg_confs/{config.WG_INTERFACE_NAME}.conf)",
            ],
        )
        if exit_code != 0:
            raise WireGuardDockerError(
                f"wg syncconf завершился с ошибкой (код {exit_code}): {output.decode('utf-8', 'replace')}"
            )
        logger.info("Конфигурация WireGuard применена на горячую (wg syncconf)")

    def get_peer_last_handshakes(self) -> dict[str, int]:
        """
        Возвращает {public_key: unix_timestamp последнего handshake}. WireGuard
        не пишет лог о каждом подключении (это не TCP-прокси, а UDP-туннель без
        событийного протокола) — время последнего handshake — самый прямой
        показатель "жив ли клиент" ("0" из вывода wg означает "ни разу").
        """
        container = self._get_container()
        if container is None:
            return {}
        try:
            exit_code, output = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME, "latest-handshakes"]
            )
        except APIError:
            return {}
        if exit_code != 0:
            return {}

        result: dict[str, int] = {}
        for line in output.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            public_key, timestamp = parts
            try:
                result[public_key] = int(timestamp)
            except ValueError:
                continue
        return result

    def get_peer_transfer_stats(self) -> dict[str, tuple[int, int]]:
        """
        Возвращает {public_key: (rx_bytes, tx_bytes)} по выводу
        `wg show <iface> transfer`. Это единственный встроенный счётчик
        трафика WireGuard — в веб-логах UDP-туннеля отдельных сессий нет.
        """
        container = self._get_container()
        if container is None:
            return {}
        try:
            exit_code, output = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME, "transfer"]
            )
        except APIError:
            return {}
        if exit_code != 0:
            return {}

        result: dict[str, tuple[int, int]] = {}
        for line in output.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            public_key, rx_raw, tx_raw = parts
            try:
                result[public_key] = (int(rx_raw), int(tx_raw))
            except ValueError:
                continue
        return result

    def _container_diagnostics(self) -> str:
        """Короткий дамп логов/статуса для текста ошибки в UI."""
        container = self._get_container()
        if container is None:
            return "контейнер отсутствует"
        try:
            container.reload()
            status = container.status
            logs = container.logs(tail=40).decode("utf-8", "replace").strip()
            code, conf = container.exec_run(
                ["bash", "-c", "ls -la /config/wg_confs/ 2>&1; echo '---'; cat /config/wg_confs/wg0.conf 2>&1 | head -20"]
            )
            conf_text = conf.decode("utf-8", "replace").strip() if code == 0 or conf else ""
            return f"status={status}\n--- docker logs ---\n{logs}\n--- config ---\n{conf_text}"
        except Exception as exc:  # noqa: BLE001
            return f"не удалось собрать диагностику: {exc}"

    def wait_until_interface_ready(
        self, timeout: float | None = None,
    ) -> None:
        """
        Ждёт, пока внутри контейнера поднимется интерфейс wg0.
        linuxserver-entrypoint поднимает wg-quick асинхронно после start.
        """
        if timeout is None:
            timeout = config.DOCKER_WG_INTERFACE_TIMEOUT_SECONDS
        container = self._get_container()
        if container is None:
            raise WireGuardDockerError("Контейнер WireGuard не найден — сервер ещё не настроен")

        deadline = time.monotonic() + timeout
        last_err = ""
        forced_up = False
        while time.monotonic() < deadline:
            container.reload()
            if container.status in {"exited", "dead"}:
                raise WireGuardDockerError(
                    f"Контейнер WireGuard упал со статусом '{container.status}' "
                    f"до подъёма wg0.\n{self._container_diagnostics()}"
                )
            exit_code, output = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME]
            )
            if exit_code == 0:
                return
            last_err = output.decode("utf-8", "replace").strip()

            # linuxserver поднимает туннель асинхронно; если за первые секунды
            # wg0 нет — форсим wg-quick up сами (часто чинит отсутствие автозапуска).
            elapsed = timeout - (deadline - time.monotonic())
            if not forced_up and elapsed >= 8.0:
                forced_up = True
                logger.info("Форсирую wg-quick up внутри контейнера WireGuard")
                self._force_wg_quick_up(container)

            time.sleep(1.0)
        raise WireGuardDockerError(
            f"Интерфейс {config.WG_INTERFACE_NAME} не поднялся за {timeout:.0f}с. "
            f"Последний ответ wg: {last_err or '(пусто)'}\n"
            f"На сервере выполните: docker logs wg_server && "
            f"ls -la /dev/net/tun && docker exec wg_server wg-quick up /config/wg_confs/wg0.conf\n"
            f"{self._container_diagnostics()}"
        )

    def _force_wg_quick_up(self, container: Container) -> None:
        """Пытается поднять туннель вручную, если entrypoint задержался/упал."""
        try:
            container.exec_run(
                [
                    "bash", "-c",
                    "test -e /dev/net/tun || "
                    "(mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 666 /dev/net/tun); "
                    f"wg-quick down /config/wg_confs/{config.WG_INTERFACE_NAME}.conf >/dev/null 2>&1 || true; "
                    f"wg-quick up /config/wg_confs/{config.WG_INTERFACE_NAME}.conf",
                ]
            )
        except APIError as exc:
            logger.warning("force wg-quick up не удался: %s", format_docker_api_error(exc))

    def ensure_nat_rules(self, subnet: str) -> None:
        """
        Гарантирует ip_forward + MASQUERADE для VPN-подсети внутри контейнера.
        PostUp из wg-quick иногда не срабатывает/срабатывает со старым eth0 —
        тогда handshake есть (килобайты transfer), а интернет на телефоне нет.
        Идемпотентно: `-C` проверяет правило перед `-A`. Обёрнуто в timeout,
        чтобы docker exec не подвешивал HTTP-запрос панели.
        """
        container = self._get_container()
        if container is None:
            raise WireGuardDockerError("Контейнер WireGuard не найден — сервер ещё не настроен")

        network_cidr = subnet if "/" in subnet else f"{subnet}/24"
        script = f"""
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT
iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
iptables -t nat -C POSTROUTING -s {network_cidr} -j MASQUERADE 2>/dev/null \\
  || iptables -t nat -A POSTROUTING -s {network_cidr} -j MASQUERADE
iptables -t nat -S POSTROUTING
"""
        exit_code, output = container.exec_run(
            ["timeout", "15", "bash", "-c", script]
        )
        text = output.decode("utf-8", "replace")
        if exit_code != 0:
            raise WireGuardDockerError(
                f"Не удалось применить NAT/forwarding внутри WireGuard-контейнера "
                f"(код {exit_code}): {text}"
            )
        logger.info("NAT/forwarding WireGuard применены: %s", text.strip().replace("\n", " | "))

    def restart_server(self) -> None:
        """Перезапускает контейнер WireGuard-сервера, не трогая конфигурацию/peer-ов."""
        container = self._get_container()
        if container is None:
            raise WireGuardDockerError("Контейнер WireGuard не найден — сервер ещё не настроен")
        try:
            container.restart(timeout=10)
        except APIError as exc:
            raise WireGuardDockerError(f"Не удалось перезапустить контейнер WireGuard: {exc}") from exc
        self._wait_running(container)

    def remove_server(self) -> None:
        """Полностью удаляет контейнер WireGuard-сервера (для полного сброса VPN)."""
        container = self._get_container()
        if container is None:
            return
        try:
            container.remove(force=True)
        except APIError as exc:
            raise WireGuardDockerError(f"Не удалось удалить контейнер WireGuard: {exc}") from exc
