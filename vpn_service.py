"""
Сервисный слой для VPN-подсистем: WireGuard и Xray/VLESS.
Routes обращаются только сюда — вся логика setup/добавления/удаления
клиентов, работы с Docker и генерации конфигов инкапсулирована здесь.
"""
from __future__ import annotations

import logging
import time

import config
import crypto_utils
import utils
import wireguard_config
import xray_config
from models import VlessClient, WireGuardPeer, WireGuardServerConfig, XrayServerConfig
from vpn_repository import AlreadyExistsError, WireGuardRepository, XrayRepository
from wireguard_manager import WireGuardDockerError, WireGuardManager
from xray_manager import XrayDockerError, XrayManager

logger = logging.getLogger(__name__)


class VpnServiceError(RuntimeError):
    """Единая ошибка VPN сервисного слоя, безопасная для показа пользователю."""


def _format_relative_time(epoch_seconds: int) -> str:
    """Человекочитаемое 'N назад' для отображения последнего handshake peer-а."""
    if not epoch_seconds:
        return "нет подключений"
    delta = max(0, int(time.time()) - epoch_seconds)
    if delta < 60:
        return "меньше минуты назад"
    minutes = delta // 60
    if minutes < 60:
        return f"{minutes} мин. назад"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} ч. назад"
    days = hours // 24
    return f"{days} дн. назад"


def _format_bytes(num_bytes: int) -> str:
    """Компактный размер для UI: 12 B / 1.5 KB / 3.2 MB / 1.1 GB."""
    value = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{num_bytes} B"


# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------
class WireGuardService:
    """Оркестрирует настройку сервера и управление peer-ами WireGuard."""

    def __init__(self) -> None:
        self._repository = WireGuardRepository()
        try:
            self._manager = WireGuardManager()
        except WireGuardDockerError as exc:
            raise VpnServiceError(str(exc)) from exc

    def get_server_config(self) -> WireGuardServerConfig | None:
        return self._repository.get_server_config()

    def get_status(self) -> str:
        return self._manager.get_status()

    def list_peers(self) -> list[WireGuardPeer]:
        return self._repository.get_all_peers()

    def get_peer_connection_labels(self) -> dict[int, str]:
        """
        {peer.id: 'N назад' / 'нет подключений'} по последнему WireGuard
        handshake — единственный доступный панели индикатор "жив ли клиент"
        для UDP-туннеля (в отличие от MTProxy/Xray, у WireGuard нет лога
        отдельных соединений).
        """
        handshakes_by_pubkey = self._manager.get_peer_last_handshakes()
        return {
            peer.id: _format_relative_time(handshakes_by_pubkey.get(peer.public_key, 0))
            for peer in self._repository.get_all_peers()
        }

    def get_peer_traffic_labels(self) -> dict[int, str]:
        """{peer.id: '↓ 1.2 MB / ↑ 340 KB'} по счётчикам WireGuard transfer."""
        transfer_by_pubkey = self._manager.get_peer_transfer_stats()
        labels: dict[int, str] = {}
        for peer in self._repository.get_all_peers():
            rx_bytes, tx_bytes = transfer_by_pubkey.get(peer.public_key, (0, 0))
            labels[peer.id] = f"↓ {_format_bytes(rx_bytes)} / ↑ {_format_bytes(tx_bytes)}"
        return labels

    def setup_server(self, *, listen_port: int, subnet: str, dns: str) -> WireGuardServerConfig:
        """
        Первоначальная настройка WireGuard-сервера: генерирует ключи,
        определяет публичный IP, поднимает контейнер. При любой ошибке —
        контейнер откатывается, запись в БД не создаётся.
        """
        try:
            utils.validate_manual_port(listen_port)
        except utils.PortUnavailableError as exc:
            raise VpnServiceError(str(exc)) from exc

        try:
            endpoint_ip = utils.get_server_public_ip()
        except utils.PublicIPLookupError as exc:
            raise VpnServiceError(str(exc)) from exc

        server_private_key, server_public_key = crypto_utils.generate_wireguard_keypair()

        server_conf_text = wireguard_config.render_server_config(
            server_private_key=server_private_key, listen_port=listen_port, subnet=subnet, peers=[],
        )
        wg_confs_dir = config.WG_CONFIG_DIR / "wg_confs"
        wg_confs_dir.mkdir(parents=True, exist_ok=True)
        (wg_confs_dir / f"{config.WG_INTERFACE_NAME}.conf").write_text(server_conf_text, encoding="utf-8")

        try:
            self._manager.ensure_server_running(listen_port)
            self._manager.wait_until_interface_ready()
            self._manager.ensure_nat_rules(subnet)
        except WireGuardDockerError as exc:
            try:
                self._manager.remove_server()
            except WireGuardDockerError:
                logger.warning("Не удалось откатить контейнер WireGuard после ошибки setup")
            raise VpnServiceError(str(exc)) from exc

        return self._repository.save_server_config(
            server_private_key=server_private_key,
            server_public_key=server_public_key,
            listen_port=listen_port,
            subnet=subnet,
            endpoint_ip=endpoint_ip,
            dns=dns,
        )

    def ensure_running_if_configured(self) -> None:
        """
        При старте панели: если WireGuard уже настроен — синхронизирует
        wg0.conf из БД на диск и поднимает контейнер. Раньше файл на диске
        мог остаться от старого/битого запуска (PEERS=0 и т.п.), а контейнер
        просто стартовал поверх него — клиенты получали ключи из БД, а
        интерфейс жил со старым конфигом.
        """
        server_config = self._repository.get_server_config()
        if server_config is None:
            return
        try:
            conf_path = config.WG_CONFIG_DIR / "wg_confs" / f"{config.WG_INTERFACE_NAME}.conf"
            old_conf = conf_path.read_text(encoding="utf-8") if conf_path.exists() else ""
            was_running = self._manager.is_running()
            self._write_server_conf(server_config)
            new_conf = conf_path.read_text(encoding="utf-8")
            self._refresh_peer_client_configs(server_config)
            self._manager.ensure_server_running(server_config.listen_port)
            self._manager.wait_until_interface_ready()
            # syncconf НЕ выполняет PostUp. При смене NAT — полный рестарт.
            needs_full_restart = was_running and (
                old_conf != new_conf
                or "-o eth0 -j MASQUERADE" in old_conf
            )
            if needs_full_restart:
                logger.info("Конфиг WireGuard изменился — полный рестарт контейнера для применения NAT")
                self._manager.restart_server()
                self._manager.wait_until_interface_ready()
            elif was_running:
                self._manager.reload_config()
            # Всегда дожимаем NAT/forwarding (idempotent) — чинит «handshake есть, интернета нет».
            self._manager.ensure_nat_rules(server_config.subnet)
        except WireGuardDockerError as exc:
            logger.error("Не удалось поднять WireGuard-сервер при старте: %s", exc)

    def _refresh_peer_client_configs(self, server_config: WireGuardServerConfig) -> None:
        """Пересобирает .conf/QR пиров (MTU/endpoint), чтобы телефон получил актуальный профиль."""
        for peer in self._repository.get_all_peers():
            new_conf = wireguard_config.render_client_config(
                client_private_key=peer.private_key,
                client_allocated_ip=peer.allocated_ip,
                server_public_key=server_config.server_public_key,
                server_endpoint_ip=server_config.endpoint_ip,
                server_listen_port=server_config.listen_port,
                dns=server_config.dns,
            )
            if new_conf == peer.config_text:
                continue
            self._repository.update_peer_config(peer.id, config_text=new_conf)
            try:
                utils.generate_qr_code(new_conf, peer.qr_filename)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Не удалось обновить QR WireGuard peer id=%d: %s", peer.id, exc)
            logger.info("Обновлён клиентский конфиг WireGuard peer '%s' (MTU/endpoint)", peer.name)

    def _write_server_conf(self, server_config: WireGuardServerConfig) -> None:
        self._manager.ensure_host_config_writable()
        peers = [
            wireguard_config.PeerForConfig(name=p.name, public_key=p.public_key, allocated_ip=p.allocated_ip)
            for p in self._repository.get_all_peers()
        ]
        server_conf_text = wireguard_config.render_server_config(
            server_private_key=server_config.server_private_key,
            listen_port=server_config.listen_port,
            subnet=server_config.subnet,
            peers=peers,
        )
        wg_confs_dir = config.WG_CONFIG_DIR / "wg_confs"
        wg_confs_dir.mkdir(parents=True, exist_ok=True)
        (wg_confs_dir / f"{config.WG_INTERFACE_NAME}.conf").write_text(server_conf_text, encoding="utf-8")
        self._manager.ensure_host_config_writable()

    def _rewrite_and_reload(self, server_config: WireGuardServerConfig) -> None:
        self._write_server_conf(server_config)
        self._manager.wait_until_interface_ready()
        self._manager.reload_config()
        self._manager.ensure_nat_rules(server_config.subnet)

    def add_peer(self, name: str) -> WireGuardPeer:
        server_config = self._repository.get_server_config()
        if server_config is None:
            raise VpnServiceError("WireGuard-сервер ещё не настроен")

        cleaned_name = name.strip()
        if not cleaned_name:
            raise VpnServiceError("Укажите имя устройства")

        used_ips = self._repository.get_used_ips()
        allocated_ip = wireguard_config.allocate_next_ip(server_config.subnet, used_ips)
        client_private_key, client_public_key = crypto_utils.generate_wireguard_keypair()

        client_conf_text = wireguard_config.render_client_config(
            client_private_key=client_private_key,
            client_allocated_ip=allocated_ip,
            server_public_key=server_config.server_public_key,
            server_endpoint_ip=server_config.endpoint_ip,
            server_listen_port=server_config.listen_port,
            dns=server_config.dns,
        )

        qr_filename = f"wg_{cleaned_name}_{allocated_ip.replace('.', '_')}.png"
        try:
            utils.generate_qr_code(client_conf_text, qr_filename)
        except Exception as exc:
            raise VpnServiceError(f"Не удалось сгенерировать QR-код: {exc}") from exc

        try:
            peer = self._repository.create_peer(
                name=cleaned_name,
                private_key=client_private_key,
                public_key=client_public_key,
                allocated_ip=allocated_ip,
                config_text=client_conf_text,
                qr_filename=qr_filename,
            )
        except AlreadyExistsError as exc:
            utils.delete_qr_code(qr_filename)
            raise VpnServiceError(str(exc)) from exc

        try:
            self._rewrite_and_reload(server_config)
        except WireGuardDockerError as exc:
            # Откатываем запись из БД и QR, чтобы не оставлять "невидимого" клиента.
            self._repository.delete_peer(peer.id)
            utils.delete_qr_code(qr_filename)
            raise VpnServiceError(f"Не удалось применить конфигурацию: {exc}") from exc

        return peer

    def delete_peer(self, peer_id: int) -> None:
        server_config = self._repository.get_server_config()
        if server_config is None:
            raise VpnServiceError("WireGuard-сервер ещё не настроен")

        peer = self._repository.delete_peer(peer_id)
        utils.delete_qr_code(peer.qr_filename)
        try:
            self._rewrite_and_reload(server_config)
        except WireGuardDockerError as exc:
            logger.error("Не удалось применить конфигурацию после удаления peer: %s", exc)
            raise VpnServiceError(f"Peer удалён из базы, но применить конфигурацию не удалось: {exc}") from exc

    def restart_server(self) -> None:
        """Перезапускает контейнер WireGuard-сервера, не трогая настройки/peer-ов."""
        server_config = self._repository.get_server_config()
        if server_config is None:
            raise VpnServiceError("WireGuard-сервер ещё не настроен")
        try:
            # Перед рестартом перезаписываем conf из БД — иначе контейнер
            # снова поднимет устаревший файл с диска.
            self._write_server_conf(server_config)
            self._manager.restart_server()
            self._manager.wait_until_interface_ready()
            self._manager.ensure_nat_rules(server_config.subnet)
        except WireGuardDockerError as exc:
            raise VpnServiceError(str(exc)) from exc

    def reset_server(self) -> None:
        """
        Полностью сбрасывает WireGuard: удаляет всех peer-ов (с QR-кодами),
        серверную конфигурацию из БД и Docker-контейнер, чтобы можно было
        настроить сервер заново с чистого листа (другой порт/подсеть/DNS).
        Удаление контейнера — best-effort: даже если оно не удастся, БД всё
        равно очищается, и следующая настройка перезапишет конфиг заново.
        """
        for peer in self._repository.get_all_peers():
            utils.delete_qr_code(peer.qr_filename)
        self._repository.delete_all_peers()
        self._repository.delete_server_config()
        try:
            self._manager.remove_server()
        except WireGuardDockerError as exc:
            logger.warning("Не удалось удалить контейнер WireGuard при сбросе конфигурации: %s", exc)


# ---------------------------------------------------------------------------
# Xray / VLESS
# ---------------------------------------------------------------------------
class XrayService:
    """Оркестрирует настройку сервера и управление VLESS-клиентами Xray."""

    def __init__(self) -> None:
        self._repository = XrayRepository()
        try:
            self._manager = XrayManager()
        except XrayDockerError as exc:
            raise VpnServiceError(str(exc)) from exc

    def get_server_config(self) -> XrayServerConfig | None:
        return self._repository.get_server_config()

    def get_status(self) -> str:
        return self._manager.get_status()

    def list_clients(self) -> list[VlessClient]:
        return self._repository.get_all_clients()

    def setup_server(self, *, listen_port: int, dest: str, server_name: str) -> XrayServerConfig:
        """
        Первоначальная настройка Xray-сервера: генерирует REALITY-ключи,
        поднимает контейнер с пустым списком клиентов. При ошибке —
        контейнер откатывается, запись в БД не создаётся.
        """
        try:
            utils.validate_manual_port(listen_port)
        except utils.PortUnavailableError as exc:
            raise VpnServiceError(str(exc)) from exc

        private_key, public_key = crypto_utils.generate_reality_keypair()
        short_id = crypto_utils.generate_reality_short_id()

        config_json = xray_config.render_server_config(
            listen_port=listen_port, dest=dest, server_names=[server_name],
            private_key=private_key, short_id=short_id, clients=[],
        )

        try:
            self._manager.ensure_server_running(listen_port, config_json)
        except XrayDockerError as exc:
            try:
                self._manager.remove_server()
            except XrayDockerError:
                logger.warning("Не удалось откатить контейнер Xray после ошибки setup")
            raise VpnServiceError(str(exc)) from exc

        return self._repository.save_server_config(
            listen_port=listen_port, dest=dest, server_names=server_name,
            private_key=private_key, public_key=public_key, short_id=short_id,
        )

    def ensure_running_if_configured(self) -> None:
        """
        При старте панели: поднимает Xray и ПРИМЕНЯЕТ актуальный config.json
        (включая текущий XRAY_FLOW). Раньше ensure_server_running при уже
        running-контейнере только перезаписывал файл на диске и выходил —
        процесс Xray продолжал жить со старым in-memory конфигом (например,
        без Vision / со старым dest), а новые клиентские ссылки уже строились
        по новому config.py → клиент и сервер расходились.
        """
        server_config = self._repository.get_server_config()
        if server_config is None:
            return

        self._refresh_client_links(server_config)

        clients_for_config = [(c.client_uuid, c.name) for c in self._repository.get_all_clients()]
        config_json = xray_config.render_server_config(
            listen_port=server_config.listen_port, dest=server_config.dest,
            server_names=[server_config.server_names], private_key=server_config.private_key,
            short_id=server_config.short_id, clients=clients_for_config,
        )
        try:
            if self._manager.is_running():
                self._manager.apply_config(config_json)
            else:
                self._manager.ensure_server_running(server_config.listen_port, config_json)
        except XrayDockerError as exc:
            logger.error("Не удалось поднять Xray-сервер при старте: %s", exc)

    def _refresh_client_links(self, server_config: XrayServerConfig) -> None:
        """
        Пересобирает сохранённые vless:// ссылки и QR под текущие настройки
        (flow/SNI/порт/pubkey). Иначе после смены XRAY_FLOW в коде старые
        ссылки в БД оставались с другим flow, и телефон продолжал слать
        несовместимый handshake.
        """
        try:
            server_ip = utils.get_server_public_ip()
        except utils.PublicIPLookupError as exc:
            logger.warning("Не удалось обновить vless:// ссылки при старте (нет публичного IP): %s", exc)
            return

        for client in self._repository.get_all_clients():
            new_link = xray_config.build_vless_link(
                client_uuid=client.client_uuid,
                server_ip=server_ip,
                listen_port=server_config.listen_port,
                public_key=server_config.public_key,
                short_id=server_config.short_id,
                server_name=server_config.server_names,
                remark=client.name,
            )
            if new_link == client.vless_link:
                continue
            self._repository.update_client_link(client.id, vless_link=new_link)
            try:
                utils.generate_qr_code(new_link, client.qr_filename)
            except Exception as exc:  # noqa: BLE001 — QR не должен валить автозапуск
                logger.warning("Не удалось обновить QR для VLESS-клиента id=%d: %s", client.id, exc)
            logger.info("Обновлена vless:// ссылка клиента '%s' под текущий XRAY_FLOW/настройки", client.name)

    def add_client(self, name: str) -> VlessClient:
        server_config = self._repository.get_server_config()
        if server_config is None:
            raise VpnServiceError("Xray-сервер ещё не настроен")

        cleaned_name = name.strip()
        if not cleaned_name:
            raise VpnServiceError("Укажите имя устройства")

        client_uuid = crypto_utils.generate_client_uuid()

        try:
            server_ip = utils.get_server_public_ip()
        except utils.PublicIPLookupError as exc:
            raise VpnServiceError(str(exc)) from exc

        vless_link = xray_config.build_vless_link(
            client_uuid=client_uuid, server_ip=server_ip, listen_port=server_config.listen_port,
            public_key=server_config.public_key, short_id=server_config.short_id,
            server_name=server_config.server_names, remark=cleaned_name,
        )

        qr_filename = f"vless_{cleaned_name}_{client_uuid[:8]}.png"
        try:
            utils.generate_qr_code(vless_link, qr_filename)
        except Exception as exc:
            raise VpnServiceError(f"Не удалось сгенерировать QR-код: {exc}") from exc

        try:
            client = self._repository.create_client(
                name=cleaned_name, client_uuid=client_uuid, vless_link=vless_link, qr_filename=qr_filename,
            )
        except AlreadyExistsError as exc:
            utils.delete_qr_code(qr_filename)
            raise VpnServiceError(str(exc)) from exc

        try:
            self._apply_client_list(server_config)
        except XrayDockerError as exc:
            self._repository.delete_client(client.id)
            utils.delete_qr_code(qr_filename)
            raise VpnServiceError(f"Не удалось применить конфигурацию: {exc}") from exc

        return client

    def delete_client(self, client_id: int) -> None:
        server_config = self._repository.get_server_config()
        if server_config is None:
            raise VpnServiceError("Xray-сервер ещё не настроен")

        client = self._repository.delete_client(client_id)
        utils.delete_qr_code(client.qr_filename)
        try:
            self._apply_client_list(server_config)
        except XrayDockerError as exc:
            logger.error("Не удалось применить конфигурацию после удаления клиента: %s", exc)
            raise VpnServiceError(f"Клиент удалён из базы, но применить конфигурацию не удалось: {exc}") from exc

    def restart_server(self) -> None:
        """Перезапускает контейнер Xray с актуальным config.json из БД."""
        server_config = self._repository.get_server_config()
        if server_config is None:
            raise VpnServiceError("Xray-сервер ещё не настроен")

        clients_for_config = [(c.client_uuid, c.name) for c in self._repository.get_all_clients()]
        config_json = xray_config.render_server_config(
            listen_port=server_config.listen_port, dest=server_config.dest,
            server_names=[server_config.server_names], private_key=server_config.private_key,
            short_id=server_config.short_id, clients=clients_for_config,
        )
        try:
            if self._manager.get_status() == "missing":
                self._manager.ensure_server_running(server_config.listen_port, config_json)
            else:
                self._manager.apply_config(config_json)
        except XrayDockerError as exc:
            raise VpnServiceError(str(exc)) from exc

    def reset_server(self) -> None:
        """
        Полностью сбрасывает Xray: удаляет всех клиентов (с QR-кодами),
        серверную конфигурацию из БД и Docker-контейнер, чтобы можно было
        настроить сервер заново с чистого листа (другой порт/dest/SNI).
        """
        for client in self._repository.get_all_clients():
            utils.delete_qr_code(client.qr_filename)
        self._repository.delete_all_clients()
        self._repository.delete_server_config()
        try:
            self._manager.remove_server()
        except XrayDockerError as exc:
            logger.warning("Не удалось удалить контейнер Xray при сбросе конфигурации: %s", exc)

    def _apply_client_list(self, server_config: XrayServerConfig) -> None:
        clients_for_config = [(c.client_uuid, c.name) for c in self._repository.get_all_clients()]
        config_json = xray_config.render_server_config(
            listen_port=server_config.listen_port, dest=server_config.dest,
            server_names=[server_config.server_names], private_key=server_config.private_key,
            short_id=server_config.short_id, clients=clients_for_config,
        )
        self._manager.apply_config(config_json)
