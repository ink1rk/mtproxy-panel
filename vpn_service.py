"""
Сервисный слой VPN:
  WireGuard — native wg-quick@wg0 (PostUp как wg-easy + DOCKER-USER)
  Xray — native systemd
  MTProxy — Docker (service.py / mtproxy.py)
"""
from __future__ import annotations

import logging
import time

import config
import crypto_utils
import utils
import vpn_health
import wireguard_config
import xray_config
from models import VlessClient, WireGuardPeer, WireGuardServerConfig, XrayServerConfig
from vpn_repository import AlreadyExistsError, WireGuardRepository, XrayRepository
from wireguard_manager import WireGuardError, WireGuardManager
from xray_manager import XrayError, XrayManager

logger = logging.getLogger(__name__)


class VpnServiceError(RuntimeError):
    """Единая ошибка VPN сервисного слоя, безопасная для показа пользователю."""


def _format_relative_time(epoch_seconds: int) -> str:
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
    value = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{num_bytes} B"


def _require_health(report: vpn_health.HealthReport) -> None:
    if not report.ok:
        raise VpnServiceError(report.format())


# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------
class WireGuardService:
    """Оркестрирует native WireGuard (рецепт NAT как у wg-easy)."""

    def __init__(self) -> None:
        self._repository = WireGuardRepository()
        try:
            self._manager = WireGuardManager()
        except WireGuardError as exc:
            raise VpnServiceError(str(exc)) from exc

    def get_server_config(self) -> WireGuardServerConfig | None:
        return self._repository.get_server_config()

    def get_status(self) -> str:
        return self._manager.get_status()

    def list_peers(self) -> list[WireGuardPeer]:
        return self._repository.get_all_peers()

    def get_peer_connection_labels(self) -> dict[int, str]:
        handshakes_by_pubkey = self._manager.get_peer_last_handshakes()
        return {
            peer.id: _format_relative_time(handshakes_by_pubkey.get(peer.public_key, 0))
            for peer in self._repository.get_all_peers()
        }

    def diagnostics(self) -> dict | None:
        """
        Встроенная диагностика вместо ручного разбора логов/iptables.
        Возвращает routing-чеки (NAT/FORWARD/MTU/...) + вердикт по каждому
        peer'у (handshake/трафик), None если сервер ещё не настроен.
        """
        server_config = self.get_server_config()
        if server_config is None:
            return None
        routing = vpn_health.diagnose_wireguard_routing(
            listen_port=server_config.listen_port, subnet=server_config.subnet,
        )
        handshakes = self._manager.get_peer_last_handshakes()
        transfers = self._manager.get_peer_transfer_stats()
        peers = []
        for peer in self._repository.get_all_peers():
            rx, tx = transfers.get(peer.public_key, (0, 0))
            peers.append(
                vpn_health.diagnose_client(
                    name=peer.name,
                    handshake_epoch=handshakes.get(peer.public_key, 0),
                    rx_bytes=rx,
                    tx_bytes=tx,
                )
            )
        return {"routing": routing, "peers": peers}

    def get_peer_traffic_labels(self) -> dict[int, str]:
        transfer_by_pubkey = self._manager.get_peer_transfer_stats()
        labels: dict[int, str] = {}
        for peer in self._repository.get_all_peers():
            rx_bytes, tx_bytes = transfer_by_pubkey.get(peer.public_key, (0, 0))
            labels[peer.id] = f"↓ {_format_bytes(rx_bytes)} / ↑ {_format_bytes(tx_bytes)}"
        return labels

    def _render_conf(self, server_config: WireGuardServerConfig) -> str:
        peers = [
            wireguard_config.PeerForConfig(
                name=p.name,
                public_key=p.public_key,
                allocated_ip=p.allocated_ip,
                preshared_key=p.preshared_key,
            )
            for p in self._repository.get_all_peers()
        ]
        return wireguard_config.render_server_config(
            server_private_key=server_config.server_private_key,
            listen_port=server_config.listen_port,
            subnet=server_config.subnet,
            peers=peers,
        )

    def _xray_listen_port(self) -> int | None:
        try:
            xray_cfg = XrayRepository().get_server_config()
        except Exception:  # noqa: BLE001
            return None
        return xray_cfg.listen_port if xray_cfg else None

    def setup_server(self, *, listen_port: int, subnet: str, dns: str) -> WireGuardServerConfig:
        try:
            utils.validate_manual_port(listen_port)
        except utils.PortUnavailableError as exc:
            raise VpnServiceError(str(exc)) from exc

        try:
            endpoint_ip = utils.get_server_public_ip()
        except utils.PublicIPLookupError as exc:
            raise VpnServiceError(str(exc)) from exc

        server_private_key, server_public_key = crypto_utils.generate_wireguard_keypair()
        conf_text = wireguard_config.render_server_config(
            server_private_key=server_private_key,
            listen_port=listen_port,
            subnet=subnet,
            peers=[],
        )

        try:
            self._manager.ensure_server_running(
                conf_text=conf_text,
                listen_port=listen_port,
                subnet=subnet,
                xray_port=self._xray_listen_port(),
            )
            _require_health(
                vpn_health.check_wireguard(listen_port=listen_port, subnet=subnet)
            )
        except (WireGuardError, VpnServiceError) as exc:
            try:
                self._manager.remove_server()
            except WireGuardError:
                logger.warning("Не удалось откатить WireGuard после ошибки setup")
            raise VpnServiceError(str(exc)) from exc

        return self._repository.save_server_config(
            server_private_key=server_private_key,
            server_public_key=server_public_key,
            listen_port=listen_port,
            subnet=subnet,
            endpoint_ip=endpoint_ip,
            dns=dns,
        )

    def ensure_ready(self) -> WireGuardPeer | None:
        """
        Без ручных шагов: сервер + peer с QR.
        Возвращает основной peer (первый / default), либо None если auto выключен.
        """
        import os

        if os.environ.get("MTPROXY_DISABLE_WG") == "1":
            logger.info("WG auto-provision disabled (MTPROXY_DISABLE_WG=1)")
            return None
        if not config.WG_AUTO_PROVISION:
            self.ensure_running_if_configured()
            peers = self.list_peers()
            return peers[0] if peers else None

        server_config = self.get_server_config()
        if server_config is None:
            logger.info("WG auto-provision: создаю сервер")
            server_config = self.setup_server(
                listen_port=config.WG_DEFAULT_PORT,
                subnet=config.WG_DEFAULT_SUBNET,
                dns=config.WG_DEFAULT_DNS,
            )

        peers = self.list_peers()
        if not peers:
            logger.info(
                "WG auto-provision: создаю peer %r", config.WG_DEFAULT_PEER_NAME,
            )
            peer = self.add_peer(config.WG_DEFAULT_PEER_NAME)
        else:
            self.ensure_running_if_configured()
            peer = peers[0]

        return peer

    def ensure_running_if_configured(self) -> None:
        # Когда на хосте крутится отдельный wg-easy — не трогаем :51820.
        import os
        if os.environ.get("MTPROXY_DISABLE_WG") == "1":
            logger.info("WG auto-start disabled (MTPROXY_DISABLE_WG=1)")
            return
        server_config = self._repository.get_server_config()
        if server_config is None:
            return
        try:
            self._refresh_peer_client_configs(server_config)
            conf_text = self._render_conf(server_config)
            self._manager.ensure_server_running(
                conf_text=conf_text,
                listen_port=server_config.listen_port,
                subnet=server_config.subnet,
                xray_port=self._xray_listen_port(),
            )
            report = vpn_health.check_wireguard(
                listen_port=server_config.listen_port,
                subnet=server_config.subnet,
            )
            if not report.ok:
                logger.error("WireGuard health при старте:\n%s", report.format())
        except WireGuardError as exc:
            logger.error("Не удалось поднять WireGuard при старте: %s", exc)

    def _refresh_peer_client_configs(self, server_config: WireGuardServerConfig) -> None:
        clients_dir = config.WG_CONFIG_DIR / "clients"
        clients_dir.mkdir(parents=True, exist_ok=True)
        for peer in self._repository.get_all_peers():
            psk = peer.preshared_key or crypto_utils.generate_wireguard_preshared_key()
            new_conf = wireguard_config.render_client_config(
                client_private_key=peer.private_key,
                client_allocated_ip=peer.allocated_ip,
                server_public_key=server_config.server_public_key,
                server_endpoint_ip=server_config.endpoint_ip,
                server_listen_port=server_config.listen_port,
                dns=server_config.dns,
                subnet=server_config.subnet,
                preshared_key=psk,
            )
            safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in peer.name)
            (clients_dir / f"{safe_name}.conf").write_text(new_conf, encoding="utf-8")
            if new_conf == peer.config_text and psk == peer.preshared_key:
                continue
            self._repository.update_peer_config(
                peer.id, config_text=new_conf, preshared_key=psk,
            )
            try:
                utils.generate_qr_code(new_conf, peer.qr_filename)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Не удалось обновить QR WireGuard peer id=%d: %s", peer.id, exc)
            logger.info(
                "Клиентский WG '%s': AllowedIPs=%s DNS=%s PSK=yes",
                peer.name, config.WG_CLIENT_ALLOWED_IPS, server_config.dns,
            )

    def _rewrite_and_reload(self, server_config: WireGuardServerConfig) -> None:
        conf_text = self._render_conf(server_config)
        self._manager.reload_config(
            conf_text=conf_text,
            listen_port=server_config.listen_port,
            subnet=server_config.subnet,
        )

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
        preshared_key = crypto_utils.generate_wireguard_preshared_key()

        client_conf_text = wireguard_config.render_client_config(
            client_private_key=client_private_key,
            client_allocated_ip=allocated_ip,
            server_public_key=server_config.server_public_key,
            server_endpoint_ip=server_config.endpoint_ip,
            server_listen_port=server_config.listen_port,
            dns=server_config.dns,
            subnet=server_config.subnet,
            preshared_key=preshared_key,
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
                preshared_key=preshared_key,
            )
        except AlreadyExistsError as exc:
            utils.delete_qr_code(qr_filename)
            raise VpnServiceError(str(exc)) from exc

        try:
            self._rewrite_and_reload(server_config)
        except WireGuardError as exc:
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
        except WireGuardError as exc:
            logger.error("Не удалось применить конфигурацию после удаления peer: %s", exc)
            raise VpnServiceError(
                f"Peer удалён из базы, но применить конфигурацию не удалось: {exc}"
            ) from exc

    def restart_server(self) -> None:
        server_config = self._repository.get_server_config()
        if server_config is None:
            raise VpnServiceError("WireGuard-сервер ещё не настроен")
        try:
            conf_text = self._render_conf(server_config)
            self._manager.ensure_server_running(
                conf_text=conf_text,
                listen_port=server_config.listen_port,
                subnet=server_config.subnet,
                xray_port=self._xray_listen_port(),
            )
            _require_health(
                vpn_health.check_wireguard(
                    listen_port=server_config.listen_port,
                    subnet=server_config.subnet,
                )
            )
        except (WireGuardError, VpnServiceError) as exc:
            raise VpnServiceError(str(exc)) from exc

    def reset_server(self) -> None:
        for peer in self._repository.get_all_peers():
            utils.delete_qr_code(peer.qr_filename)
        self._repository.delete_all_peers()
        self._repository.delete_server_config()
        try:
            self._manager.remove_server()
        except WireGuardError as exc:
            logger.warning("Не удалось остановить WireGuard при сбросе: %s", exc)


# ---------------------------------------------------------------------------
# Xray / VLESS
# ---------------------------------------------------------------------------
class XrayService:
    """Оркестрирует native Xray (systemd + VLESS+REALITY)."""

    def __init__(self) -> None:
        self._repository = XrayRepository()
        try:
            self._manager = XrayManager()
        except XrayError as exc:
            raise VpnServiceError(str(exc)) from exc

    def get_server_config(self) -> XrayServerConfig | None:
        return self._repository.get_server_config()

    def get_status(self) -> str:
        return self._manager.get_status()

    def list_clients(self) -> list[VlessClient]:
        return self._repository.get_all_clients()

    def _wg_context(self) -> tuple[int | None, str | None]:
        try:
            wg = WireGuardRepository().get_server_config()
        except Exception:  # noqa: BLE001
            return None, None
        if wg is None:
            return None, None
        return wg.listen_port, wg.subnet

    def setup_server(self, *, listen_port: int, dest: str, server_name: str) -> XrayServerConfig:
        try:
            utils.validate_manual_port(listen_port)
        except utils.PortUnavailableError as exc:
            raise VpnServiceError(str(exc)) from exc

        private_key, public_key = crypto_utils.generate_reality_keypair()
        short_id = crypto_utils.generate_reality_short_id()

        config_json = xray_config.render_server_config(
            listen_port=listen_port,
            dest=dest,
            server_names=[server_name],
            private_key=private_key,
            short_id=short_id,
            clients=[],
        )
        wg_port, wg_subnet = self._wg_context()

        try:
            self._manager.ensure_server_running(
                listen_port,
                config_json,
                wg_port=wg_port,
                wg_subnet=wg_subnet,
            )
            _require_health(vpn_health.check_xray(listen_port=listen_port))
        except (XrayError, VpnServiceError) as exc:
            try:
                self._manager.remove_server()
            except XrayError:
                logger.warning("Не удалось откатить Xray после ошибки setup")
            raise VpnServiceError(str(exc)) from exc

        return self._repository.save_server_config(
            listen_port=listen_port,
            dest=dest,
            server_names=server_name,
            private_key=private_key,
            public_key=public_key,
            short_id=short_id,
        )

    def ensure_ready(self) -> VlessClient | None:
        """
        Без ручных шагов: сервер + клиент с QR (аналог WireGuardService.ensure_ready).
        """
        if not config.XRAY_AUTO_PROVISION:
            self.ensure_running_if_configured()
            clients = self.list_clients()
            return clients[0] if clients else None

        server_config = self.get_server_config()
        if server_config is None:
            logger.info("Xray auto-provision: создаю сервер")
            try:
                server_config = self.setup_server(
                    listen_port=config.XRAY_DEFAULT_PORT,
                    dest=config.XRAY_DEFAULT_DEST,
                    server_name=config.XRAY_DEFAULT_SERVER_NAMES[0],
                )
            except VpnServiceError as exc:
                logger.error("Xray auto-provision setup_server: %s", exc)
                return None

        clients = self.list_clients()
        if not clients:
            logger.info(
                "Xray auto-provision: создаю клиента %r", config.XRAY_DEFAULT_CLIENT_NAME,
            )
            try:
                client = self.add_client(config.XRAY_DEFAULT_CLIENT_NAME)
            except VpnServiceError as exc:
                logger.error("Xray auto-provision add_client: %s", exc)
                return None
        else:
            self.ensure_running_if_configured()
            client = clients[0]

        return client

    def ensure_running_if_configured(self) -> None:
        server_config = self._repository.get_server_config()
        if server_config is None:
            return

        self._refresh_client_links(server_config)
        clients_for_config = [(c.client_uuid, c.name) for c in self._repository.get_all_clients()]
        config_json = xray_config.render_server_config(
            listen_port=server_config.listen_port,
            dest=server_config.dest,
            server_names=[server_config.server_names],
            private_key=server_config.private_key,
            short_id=server_config.short_id,
            clients=clients_for_config,
        )
        wg_port, wg_subnet = self._wg_context()
        try:
            self._manager.ensure_server_running(
                server_config.listen_port,
                config_json,
                wg_port=wg_port,
                wg_subnet=wg_subnet,
            )
            report = vpn_health.check_xray(listen_port=server_config.listen_port)
            if not report.ok:
                logger.error("Xray health при старте:\n%s", report.format())
        except XrayError as exc:
            logger.error("Не удалось поднять Xray при старте: %s", exc)

    def _refresh_client_links(self, server_config: XrayServerConfig) -> None:
        try:
            server_ip = utils.get_server_public_ip()
        except utils.PublicIPLookupError as exc:
            logger.warning("Не удалось обновить vless:// ссылки: %s", exc)
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
            except Exception as exc:  # noqa: BLE001
                logger.warning("Не удалось обновить QR VLESS id=%d: %s", client.id, exc)

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
            client_uuid=client_uuid,
            server_ip=server_ip,
            listen_port=server_config.listen_port,
            public_key=server_config.public_key,
            short_id=server_config.short_id,
            server_name=server_config.server_names,
            remark=cleaned_name,
        )

        qr_filename = f"vless_{cleaned_name}_{client_uuid[:8]}.png"
        try:
            utils.generate_qr_code(vless_link, qr_filename)
        except Exception as exc:
            raise VpnServiceError(f"Не удалось сгенерировать QR-код: {exc}") from exc

        try:
            client = self._repository.create_client(
                name=cleaned_name,
                client_uuid=client_uuid,
                vless_link=vless_link,
                qr_filename=qr_filename,
            )
        except AlreadyExistsError as exc:
            utils.delete_qr_code(qr_filename)
            raise VpnServiceError(str(exc)) from exc

        try:
            self._apply_client_list(server_config)
        except XrayError as exc:
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
        except XrayError as exc:
            logger.error("Не удалось применить конфигурацию после удаления клиента: %s", exc)
            raise VpnServiceError(
                f"Клиент удалён из базы, но применить конфигурацию не удалось: {exc}"
            ) from exc

    def restart_server(self) -> None:
        server_config = self._repository.get_server_config()
        if server_config is None:
            raise VpnServiceError("Xray-сервер ещё не настроен")
        try:
            self._apply_client_list(server_config)
            _require_health(vpn_health.check_xray(listen_port=server_config.listen_port))
        except (XrayError, VpnServiceError) as exc:
            raise VpnServiceError(str(exc)) from exc

    def reset_server(self) -> None:
        for client in self._repository.get_all_clients():
            utils.delete_qr_code(client.qr_filename)
        self._repository.delete_all_clients()
        self._repository.delete_server_config()
        try:
            self._manager.remove_server()
        except XrayError as exc:
            logger.warning("Не удалось остановить Xray при сбросе: %s", exc)

    def _apply_client_list(self, server_config: XrayServerConfig) -> None:
        clients_for_config = [(c.client_uuid, c.name) for c in self._repository.get_all_clients()]
        config_json = xray_config.render_server_config(
            listen_port=server_config.listen_port,
            dest=server_config.dest,
            server_names=[server_config.server_names],
            private_key=server_config.private_key,
            short_id=server_config.short_id,
            clients=clients_for_config,
        )
        wg_port, wg_subnet = self._wg_context()
        self._manager.apply_config(
            config_json,
            listen_port=server_config.listen_port,
            wg_port=wg_port,
            wg_subnet=wg_subnet,
        )
