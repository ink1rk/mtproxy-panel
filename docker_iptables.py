"""
Починка Docker iptables — проверенный фикс ошибки:

  Unable to enable DNAT rule: iptables -t nat -A DOCKER ...
  iptables: No chain/target/match by that name

На Ubuntu 20.04+/24.04+/26.04 Docker часто ломается, когда
iptables указывает на nft-backend, а цепочки DOCKER сброшены.

Источники:
  - errornotes.dev: iptables-legacy + systemctl restart docker
  - InfraRunBook / Docker forums: same recipe
"""
from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class DockerIptablesError(RuntimeError):
    pass


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise DockerIptablesError(
            f"{' '.join(cmd)} failed: {(result.stderr or result.stdout).strip()}"
        )
    return result


def docker_nat_chain_exists() -> bool:
    """True если цепочка nat/DOCKER доступна текущему iptables."""
    result = _run(["iptables", "-t", "nat", "-L", "DOCKER", "-n"], check=False)
    return result.returncode == 0


def _iptables_backend() -> str:
    result = _run(["iptables", "-V"], check=False)
    text = (result.stdout or result.stderr or "").lower()
    if "legacy" in text:
        return "legacy"
    if "nf_tables" in text or "nft" in text:
        return "nft"
    return "unknown"


def ensure_iptables_legacy() -> bool:
    """Переключает систему на iptables-legacy (если бинарь есть)."""
    backend = _iptables_backend()
    if backend == "legacy":
        logger.info("iptables уже legacy")
        return True

    legacy = Path("/usr/sbin/iptables-legacy")
    legacy6 = Path("/usr/sbin/ip6tables-legacy")
    if not legacy.exists():
        logger.warning("iptables-legacy не найден — пропускаю switch")
        return False

    alts = _run(["bash", "-lc", "command -v update-alternatives"], check=False)
    if alts.returncode != 0:
        logger.warning("update-alternatives нет — пропускаю switch")
        return False

    logger.warning(
        "iptables backend=%s — переключаю на legacy (фикс Docker DOCKER/DNAT)",
        backend,
    )
    _run(["update-alternatives", "--set", "iptables", str(legacy)], check=False)
    if legacy6.exists():
        _run(["update-alternatives", "--set", "ip6tables", str(legacy6)], check=False)
    return True


def restart_docker() -> None:
    _run(["systemctl", "restart", "docker"], check=True)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        ping = _run(["docker", "info"], check=False)
        if ping.returncode == 0:
            return
        time.sleep(1)
    raise DockerIptablesError("Docker не поднялся после restart")


def ensure_docker_iptables(*, force_repair: bool = False) -> dict[str, str]:
    """
    Гарантирует, что Docker может публиковать порты (есть nat/DOCKER).

    Порядок (проверенные гайды):
      1) проверить DOCKER chain
      2) если нет — iptables-legacy + systemctl restart docker
      3) повторно проверить
    """
    info = {
        "backend_before": _iptables_backend(),
        "docker_chain_before": "yes" if docker_nat_chain_exists() else "no",
        "repaired": "no",
        "backend_after": "",
        "docker_chain_after": "",
    }

    if docker_nat_chain_exists() and not force_repair:
        info["backend_after"] = info["backend_before"]
        info["docker_chain_after"] = "yes"
        return info

    ensure_iptables_legacy()
    restart_docker()
    info["repaired"] = "yes"
    info["backend_after"] = _iptables_backend()
    info["docker_chain_after"] = "yes" if docker_nat_chain_exists() else "no"

    if info["docker_chain_after"] != "yes":
        raise DockerIptablesError(
            "После restart docker цепочка nat/DOCKER всё ещё отсутствует. "
            "Проверьте ufw/firewalld/nft, не делают ли iptables -F после Docker. "
            f"backend={info['backend_after']}"
        )
    return info
