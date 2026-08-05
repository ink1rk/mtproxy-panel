"""
Выполнение привилегированных host-команд для native VPN-стека.

Панель должна работать от root (systemd-юнит без User=) либо иметь sudo
без пароля. Docker остаётся только для MTProxy.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class HostExecError(RuntimeError):
    """Ошибка выполнения команды на хосте."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        return (self.stdout or self.stderr).strip()


def is_root() -> bool:
    return os.geteuid() == 0


def which(binary: str) -> str | None:
    return shutil.which(binary)


def require_binaries(*names: str) -> None:
    missing = [name for name in names if which(name) is None]
    if missing:
        raise HostExecError(
            "Не установлены обязательные утилиты: "
            + ", ".join(missing)
            + ". Запустите bash install.sh"
        )


def run(
    args: list[str],
    *,
    check: bool = True,
    timeout: float | None = 60.0,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """
    Запускает команду. Если процесс панели не root — оборачивает в sudo -n.
    """
    cmd = list(args)
    if not is_root():
        if which("sudo") is None:
            raise HostExecError(
                "Панель запущена не от root и sudo недоступен. "
                "Переустановите через bash install.sh (systemd от root)."
            )
        cmd = ["sudo", "-n", *cmd]

    logger.debug("host_exec: %s", " ".join(cmd))
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout,
            input=input_text,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise HostExecError(f"Таймаут команды: {' '.join(args)}") from exc
    except FileNotFoundError as exc:
        raise HostExecError(f"Команда не найдена: {args[0]}") from exc

    result = CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
    if check and not result.ok:
        detail = result.output or f"exit={result.returncode}"
        raise HostExecError(f"Команда {' '.join(args)} завершилась ошибкой: {detail}")
    return result


def write_root_file(path: str, content: str, *, mode: int = 0o600) -> None:
    """Атомарно пишет файл от root (через временный файл + install/mv)."""
    import tempfile
    from pathlib import Path

    target = Path(path)
    if is_root():
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".mtproxy-", dir=str(target.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            os.chmod(tmp_name, mode)
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        return

    # Не-root: пишем во временный файл пользователя и копируем через sudo install.
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(content)
        tmp_path = handle.name
    try:
        run(["mkdir", "-p", str(target.parent)])
        run(["install", "-m", f"{mode:o}", tmp_path, path])
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def remove_root_file(path: str) -> None:
    run(["rm", "-f", path], check=False)


def systemctl(*args: str, check: bool = True) -> CommandResult:
    return run(["systemctl", *args], check=check)


def journalctl_unit(unit: str, *, lines: int = 80) -> list[str]:
    result = run(
        ["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "-o", "short-iso"],
        check=False,
    )
    if not result.ok:
        return [f"[journalctl {unit}: {result.output}]"]
    return [line for line in result.stdout.splitlines() if line.strip()]
