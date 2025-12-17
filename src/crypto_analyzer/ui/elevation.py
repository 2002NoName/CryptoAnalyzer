"""Obsługa podnoszenia uprawnień dla aplikacji GUI."""

from __future__ import annotations

import os
import sys
import ctypes
from typing import Sequence


def is_running_as_admin() -> bool:
    """Sprawdza, czy bieżący proces ma uprawnienia administratora."""

    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # pragma: no cover - zależne od środowiska
            return False
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0  # type: ignore[attr-defined]
    return False


def request_elevation(extra_args: Sequence[str] | None = None) -> bool:
    """Próbuje ponownie uruchomić aplikację z uprawnieniami administratora.

    Zwraca True, jeśli próba została podjęta (nowy proces został uruchomiony).
    """

    if os.name != "nt":  # pragma: no cover - obecnie wspieramy wznawianie tylko na Windows
        return False

    params = ["-m", "crypto_analyzer.gui"]
    if extra_args:
        params.extend(extra_args)
    arguments = " ".join(params)

    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            arguments,
            None,
            1,
        )
    except Exception:  # pragma: no cover - zależne od środowiska
        return False

    return result > 32


__all__ = ["is_running_as_admin", "request_elevation"]
