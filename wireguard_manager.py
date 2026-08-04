"""
WireGuard в Docker — копия рабочего рецепта wg-easy:

  docker run \\
    --cap-add=NET_ADMIN --cap-add=SYS_MODULE \\
    --sysctl net.ipv4.conf.all.src_valid_mark=1 \\
    --sysctl net.ipv4.ip_forward=1 \\
    -p 51820:51820/udp \\
    ...

PostUp — default из wg-easy v14 config.js.
Перед bridge-publish чиним Docker iptables (iptables-legacy + restart),
иначе на Ubuntu появляется:
  Unable to enable DNAT rule ... No chain/target/match by that name

Fallback: network_mode=host (если publish всё ещё невозможен).
Native wg-quick@wg0 глушится (конфликт UDP).
"""
from __future__ import annotations

import logging
import time

import docker
from docker.errors import APIError, NotFound
from docker.models.containers import Container
from docker.types import LogConfig

import config
import host_exec
from docker_iptables import (
    DockerIptablesError,
    docker_nat_chain_exists,
    ensure_docker_iptables,
)
from docker_utils import ensure_image, format_docker_api_error

logger = logging.getLogger(__name__)


class WireGuardError(RuntimeError):
    """Ошибка WireGuard Docker-сервера."""


WireGuardDockerError = WireGuardError


def _log_config() -> LogConfig:
    return LogConfig(
        type=LogConfig.types.JSON,
        config=config.DOCKER_LOG_CONFIG["config"],
    )


class WireGuardManager:
    def __init__(self) -> None:
        try:
            self._client = docker.from_env()
            self._client.ping()
        except Exception as exc:
            raise WireGuardError(
                "Docker недоступен для WireGuard. Нужен Docker как у wg-easy."
            ) from exc

    def _get_container(self) -> Container | None:
        try:
            return self._client.containers.get(config.WG_CONTAINER_NAME)
        except NotFound:
            return None

    def is_running(self) -> bool:
        return self.get_status() == "running"

    def get_status(self) -> str:
        container = self._get_container()
        if container is None:
            return "missing"
        container.reload()
        return container.status

    def _stop_native_wg_quick(self) -> None:
        try:
            host_exec.systemctl("disable", "--now", config.WG_SYSTEMD_UNIT, check=False)
            host_exec.run(["wg-quick", "down", config.WG_INTERFACE_NAME], check=False)
            host_exec.run(
                ["ip", "link", "delete", "dev", config.WG_INTERFACE_NAME],
                check=False,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Не удалось остановить native wg-quick: %s", exc)

    def _force_remove_container(self) -> None:
        container = self._get_container()
        if container is not None:
            try:
                container.remove(force=True)
                return
            except APIError as exc:
                logger.warning(
                    "API remove WG failed (%s), docker rm -f",
                    format_docker_api_error(exc),
                )
        host_exec.run(["docker", "rm", "-f", config.WG_CONTAINER_NAME], check=False)

    def _container_network_mode(self, container: Container) -> str:
        try:
            container.reload()
        except APIError:
            return ""
        return str((container.attrs.get("HostConfig") or {}).get("NetworkMode") or "")

    def write_config(self, conf_text: str) -> None:
        wg_confs = config.WG_CONFIG_DIR / "wg_confs"
        wg_confs.mkdir(parents=True, exist_ok=True)
        path = wg_confs / f"{config.WG_INTERFACE_NAME}.conf"
        path.write_text(conf_text, encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def _prepare_docker_for_bridge(self) -> None:
        """Проверенный фикс DNAT перед publish UDP."""
        try:
            info = ensure_docker_iptables(force_repair=False)
            logger.info("Docker iptables: %s", info)
            if info.get("repaired") == "yes":
                # После systemctl restart docker SDK-клиент надо пересоздать.
                self._client = docker.from_env()
                self._client.ping()
        except DockerIptablesError as exc:
            logger.error("Docker iptables repair failed: %s", exc)
            raise WireGuardError(
                f"Docker не может публиковать порты (DOCKER/DNAT): {exc}"
            ) from exc

    def _run_kwargs(self, *, listen_port: int, network_mode: str) -> dict:
        kwargs: dict = dict(
            image=config.WG_DOCKER_IMAGE,
            name=config.WG_CONTAINER_NAME,
            detach=True,
            restart_policy={"Name": "unless-stopped"},
            cap_add=["NET_ADMIN", "SYS_MODULE"],
            # Как официальный docker run wg-easy — без PEERS у linuxserver
            environment={"PUID": "0", "PGID": "0"},
            volumes={
                str(config.WG_CONFIG_DIR): {"bind": "/config", "mode": "rw"},
                "/lib/modules": {"bind": "/lib/modules", "mode": "ro"},
            },
            log_config=_log_config(),
        )
        if network_mode == "host":
            kwargs["network_mode"] = "host"
            # sysctl в host-net Docker запрещает — на хосте уже выставляем
            host_exec.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
            host_exec.run(
                ["sysctl", "-w", "net.ipv4.conf.all.src_valid_mark=1"],
                check=False,
            )
        else:
            kwargs["network_mode"] = "bridge"
            kwargs["ports"] = {f"{listen_port}/udp": listen_port}
            kwargs["sysctls"] = {
                "net.ipv4.conf.all.src_valid_mark": "1",
                "net.ipv4.ip_forward": "1",
            }
        return kwargs

    def _create_container(self, run_kwargs: dict) -> Container:
        try:
            return self._client.containers.run(
                **run_kwargs,
                devices=["/dev/net/tun:/dev/net/tun"],
            )
        except APIError as tun_exc:
            logger.warning(
                "WG с /dev/net/tun не стартовал (%s), пробую без devices",
                format_docker_api_error(tun_exc),
            )
            self._force_remove_container()
            try:
                return self._client.containers.run(**run_kwargs)
            except APIError as exc:
                self._force_remove_container()
                raise WireGuardError(
                    f"Не удалось создать контейнер WG: {format_docker_api_error(exc)}"
                ) from exc

    def ensure_server_running(
        self,
        *,
        conf_text: str,
        listen_port: int,
        subnet: str,
        xray_port: int | None = None,  # noqa: ARG002
    ) -> None:
        self._stop_native_wg_quick()
        self.write_config(conf_text)

        preferred = config.WG_NETWORK_MODE  # "bridge" (wg-easy) или "host"
        container = self._get_container()
        if container is not None:
            container.reload()
            mode = self._container_network_mode(container)
            # default bridge often reported as "default" / "bridge"
            normalized = "bridge" if mode in {"", "default", "bridge"} else mode
            if container.status == "running":
                if normalized == preferred:
                    self._sync_and_nat(container, subnet, listen_port=listen_port)
                    return
                # Рабочий host-fallback не трогаем, пока Docker DNAT мёртв.
                if (
                    normalized == "host"
                    and preferred == "bridge"
                    and not docker_nat_chain_exists()
                ):
                    logger.warning(
                        "WG работает в host (fallback): nat/DOCKER нет — оставляю"
                    )
                    self._sync_and_nat(container, subnet, listen_port=listen_port)
                    return
            logger.warning(
                "Контейнер WG status=%s network_mode=%s (want %s) — пересоздаю",
                container.status,
                mode or "?",
                preferred,
            )
            self._force_remove_container()

        ensure_image(self._client, config.WG_DOCKER_IMAGE)

        modes_to_try = ["bridge", "host"] if preferred == "bridge" else ["host"]

        last_error: Exception | None = None
        for mode in modes_to_try:
            try:
                if mode == "bridge":
                    self._prepare_docker_for_bridge()
                logger.info(
                    "Создаю WG Docker mode=%s udp/%d wan=%s (как wg-easy)",
                    mode,
                    listen_port,
                    config.WG_DOCKER_WAN_IFACE,
                )
                run_kwargs = self._run_kwargs(listen_port=listen_port, network_mode=mode)
                container = self._create_container(run_kwargs)
                self._wait_running(container)
                self._ensure_config_writable(container)
                self.wait_until_interface_ready()
                self._ensure_nat_inside(subnet, listen_port=listen_port)
                return
            except (WireGuardError, APIError, RuntimeError, DockerIptablesError) as exc:
                last_error = exc
                logger.error("WG mode=%s failed: %s", mode, exc)
                self._force_remove_container()
                continue

        raise WireGuardError(
            f"Не удалось поднять WireGuard ни в bridge, ни в host: {last_error}"
        )

    def _sync_and_nat(
        self, container: Container, subnet: str, *, listen_port: int,
    ) -> None:
        self._ensure_config_writable(container)
        code, out = container.exec_run(
            [
                "bash", "-c",
                f"wg syncconf {config.WG_INTERFACE_NAME} "
                f"<(wg-quick strip /config/wg_confs/{config.WG_INTERFACE_NAME}.conf)",
            ]
        )
        if code != 0:
            logger.warning("syncconf: %s — restart", out.decode("utf-8", "replace"))
            container.restart(timeout=10)
            self._wait_running(container)
            self.wait_until_interface_ready()
        self._ensure_nat_inside(subnet, listen_port=listen_port)

    def _ensure_config_writable(self, container: Container) -> None:
        try:
            container.exec_run(["chmod", "-R", "a+rwX", "/config"])
        except APIError:
            pass

    def _wait_running(self, container: Container) -> None:
        deadline = time.monotonic() + config.WG_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            container.reload()
            if container.status == "running":
                return
            if container.status in {"exited", "dead"}:
                logs = container.logs(tail=40).decode("utf-8", "replace")
                raise WireGuardError(
                    f"Контейнер WG упал ({container.status}):\n{logs}"
                )
            time.sleep(0.5)
        raise WireGuardError("Контейнер WG не стал running вовремя")

    def wait_until_interface_ready(self, timeout: float | None = None) -> None:
        if timeout is None:
            timeout = config.WG_INTERFACE_TIMEOUT_SECONDS
        container = self._get_container()
        if container is None:
            raise WireGuardError("Контейнер WG не найден")
        deadline = time.monotonic() + timeout
        last = ""
        forced = False
        while time.monotonic() < deadline:
            container.reload()
            if container.status in {"exited", "dead"}:
                logs = container.logs(tail=40).decode("utf-8", "replace")
                raise WireGuardError(f"Контейнер WG упал:\n{logs}")
            code, out = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME]
            )
            if code == 0:
                return
            last = out.decode("utf-8", "replace")
            elapsed = timeout - (deadline - time.monotonic())
            if not forced and elapsed >= 5.0:
                forced = True
                container.exec_run(
                    [
                        "bash", "-c",
                        f"wg-quick up /config/wg_confs/{config.WG_INTERFACE_NAME}.conf "
                        f"|| true",
                    ]
                )
            time.sleep(1.0)
        raise WireGuardError(
            f"wg0 не поднялся за {timeout:.0f}с: {last}\n"
            f"{container.logs(tail=30).decode('utf-8', 'replace')}"
        )

    def _resolve_wan_iface(self, container: Container) -> str:
        wan = config.WG_DOCKER_WAN_IFACE
        code, _ = container.exec_run(["ip", "link", "show", "dev", wan])
        if code == 0:
            return wan
        code, out = container.exec_run(
            [
                "bash", "-c",
                "ip -4 route show default | awk '{for(i=1;i<=NF;i++) "
                "if($i==\"dev\"){print $(i+1); exit}}'",
            ]
        )
        detected = out.decode("utf-8", "replace").strip() if code == 0 else ""
        if detected:
            logger.warning("WAN %s нет внутри контейнера, использую %s", wan, detected)
            return detected
        return wan

    def _ensure_nat_inside(self, subnet: str, *, listen_port: int) -> None:
        """Идемпотентно дожимает те же правила, что PostUp wg-easy."""
        container = self._get_container()
        if container is None:
            return
        network_cidr = subnet if "/" in subnet else f"{subnet}/24"
        wan = self._resolve_wan_iface(container)
        script = f"""
set -e
iptables -P FORWARD ACCEPT 2>/dev/null || true
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
iptables -t nat -C POSTROUTING -s {network_cidr} -o {wan} -j MASQUERADE 2>/dev/null \\
  || iptables -t nat -A POSTROUTING -s {network_cidr} -o {wan} -j MASQUERADE
iptables -C INPUT -p udp -m udp --dport {listen_port} -j ACCEPT 2>/dev/null \\
  || iptables -A INPUT -p udp -m udp --dport {listen_port} -j ACCEPT
iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT
echo NAT_OK wan={wan}
iptables -t nat -S POSTROUTING
wg show || true
"""
        code, out = container.exec_run(["bash", "-c", script])
        text = out.decode("utf-8", "replace")
        if code != 0:
            raise WireGuardError(f"NAT (wg-easy PostUp) не применился: {text}")
        logger.info("WG NAT: %s", text.strip().replace("\n", " | "))

    def reload_config(self, *, conf_text: str, listen_port: int, subnet: str) -> None:
        self.write_config(conf_text)
        container = self._get_container()
        if container is None or not self.is_running():
            self.ensure_server_running(
                conf_text=conf_text, listen_port=listen_port, subnet=subnet,
            )
            return
        self._ensure_config_writable(container)
        code, out = container.exec_run(
            [
                "bash", "-c",
                f"wg syncconf {config.WG_INTERFACE_NAME} "
                f"<(wg-quick strip /config/wg_confs/{config.WG_INTERFACE_NAME}.conf)",
            ]
        )
        if code != 0:
            logger.warning("syncconf failed (%s) — ensure recreate", out)
            self.ensure_server_running(
                conf_text=conf_text, listen_port=listen_port, subnet=subnet,
            )
            return
        self._ensure_nat_inside(subnet, listen_port=listen_port)

    def get_peer_last_handshakes(self) -> dict[str, int]:
        container = self._get_container()
        if container is None:
            return {}
        try:
            code, out = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME, "latest-handshakes"]
            )
        except APIError:
            return {}
        if code != 0:
            return {}
        result: dict[str, int] = {}
        for line in out.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                continue
        return result

    def get_peer_transfer_stats(self) -> dict[str, tuple[int, int]]:
        container = self._get_container()
        if container is None:
            return {}
        try:
            code, out = container.exec_run(
                ["wg", "show", config.WG_INTERFACE_NAME, "transfer"]
            )
        except APIError:
            return {}
        if code != 0:
            return {}
        result: dict[str, tuple[int, int]] = {}
        for line in out.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            try:
                result[parts[0]] = (int(parts[1]), int(parts[2]))
            except ValueError:
                continue
        return result

    def restart_server(self) -> None:
        container = self._get_container()
        if container is None:
            raise WireGuardError("Контейнер WG не найден")
        try:
            container.restart(timeout=10)
        except APIError as exc:
            raise WireGuardError(f"Не удалось перезапустить WG: {exc}") from exc
        self._wait_running(container)
        self.wait_until_interface_ready()

    def remove_server(self) -> None:
        self._force_remove_container()
