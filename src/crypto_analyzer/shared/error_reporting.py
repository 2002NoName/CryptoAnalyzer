from __future__ import annotations

import json
import os
import platform
import sys
import threading
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any
from uuid import uuid4

try:  # stdlib, but optional in restricted envs
    import faulthandler
except Exception:  # pragma: no cover
    faulthandler = None  # type: ignore[assignment]


@dataclass(frozen=True, slots=True)
class ErrorReport:
    path: Path
    created_at: datetime


_ORIGINAL_SYS_EXCEPTHOOK = None
_FAULTHANDLER_FILE = None


def get_error_reports_dir() -> Path:
    """Returns a writable directory for error reports.

    Priority:
    1) `CRYPTOANALYZER_ERROR_DIR` env var
    2) Project root: `./error_reports` (next to `pyproject.toml`)
    3) Windows fallback: `%LOCALAPPDATA%/CryptoAnalyzer/error_reports` (or `%APPDATA%/...`)
    4) Other OS fallback: `~/.crypto_analyzer/error_reports`
    """

    override = (os.getenv("CRYPTOANALYZER_ERROR_DIR") or "").strip()
    if override:
        base = Path(override)
    else:
        project_root = _find_project_root()
        base: Path
        if project_root is not None:
            base = project_root / "error_reports"
        else:
            if os.name == "nt":
                root = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or str(Path.home())
                base = Path(root) / "CryptoAnalyzer" / "error_reports"
            else:
                base = Path.home() / ".crypto_analyzer" / "error_reports"

    base.mkdir(parents=True, exist_ok=True)
    return base


def _find_project_root() -> Path | None:
    """Returns the nearest directory containing `pyproject.toml` (best-effort)."""

    for start in (Path.cwd(), Path(__file__).resolve().parent):
        current = start
        for _ in range(25):
            if (current / "pyproject.toml").is_file():
                return current
            if current.parent == current:
                break
            current = current.parent
    return None


def _safe_app_version() -> str:
    try:
        return metadata.version("crypto-analyzer")
    except Exception:
        return "unknown"


def _sanitize_context(context: dict[str, Any]) -> dict[str, Any]:
    # Never include secrets; only include presence flags.
    env_presence = {}
    for key in (
        "CRYPTOAI_API_KEY",
        "OPENAI_API_KEY",
        "CRYPTOAI_ENDPOINT",
        "OPENAI_ENDPOINT",
        "OPENAI_BASE_URL",
        "CRYPTOAI_MODEL",
        "OPENAI_MODEL",
    ):
        val = os.getenv(key)
        env_presence[key] = bool(val and val.strip())

    out = dict(context)
    out.setdefault("env_presence", env_presence)
    return out


def write_error_report(
    error: BaseException,
    *,
    where: str,
    context: dict[str, Any] | None = None,
) -> ErrorReport:
    """Writes a timestamped error report and returns its path."""

    reports_dir = get_error_reports_dir()
    created_at = datetime.now(timezone.utc)
    stamp = created_at.strftime("%Y%m%d_%H%M%S")
    name = f"error_{stamp}_{uuid4().hex[:8]}.txt"
    path = reports_dir / name

    ctx = _sanitize_context(context or {})

    header = {
        "created_at": created_at.isoformat(),
        "where": where,
        "app_version": _safe_app_version(),
        "python": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "executable": sys.executable,
        "cwd": str(Path.cwd()),
        "context": ctx,
        "error_type": type(error).__name__,
        "error_message": str(error),
    }

    tb = "".join(traceback.format_exception(type(error), error, error.__traceback__))

    content = (
        "CryptoAnalyzer Error Report\n"
        "==========================\n\n"
        + json.dumps(header, ensure_ascii=False, indent=2)
        + "\n\nTraceback\n---------\n"
        + tb
    )

    path.write_text(content, encoding="utf-8", errors="replace")
    return ErrorReport(path=path, created_at=created_at)


def install_crash_reporting(*, enable_faulthandler: bool = True) -> None:
    """Installs best-effort crash reporting.

    Covers:
    - Unhandled Python exceptions in main thread (`sys.excepthook`)
    - Unhandled Python exceptions in background threads (`threading.excepthook`)
    - Native crashes (segfault/abort) via `faulthandler` when available

    Notes:
    - Never raises; failures here must not prevent app startup.
    - Can be disabled with `CRYPTOANALYZER_DISABLE_CRASH_HOOKS=1`.
    """

    if (os.getenv("CRYPTOANALYZER_DISABLE_CRASH_HOOKS") or "").strip().lower() in {"1", "true", "yes", "on"}:
        return

    # Avoid noisy interference in test runs unless explicitly enabled.
    if os.getenv("PYTEST_CURRENT_TEST") and (os.getenv("CRYPTOANALYZER_ENABLE_CRASH_HOOKS") or "").strip() != "1":
        return

    global _ORIGINAL_SYS_EXCEPTHOOK
    if _ORIGINAL_SYS_EXCEPTHOOK is None:
        _ORIGINAL_SYS_EXCEPTHOOK = sys.excepthook

    def _sys_excepthook(exc_type, exc, tb):  # type: ignore[no-untyped-def]
        try:
            write_error_report(
                exc if isinstance(exc, BaseException) else RuntimeError(str(exc)),
                where="sys.excepthook",
                context={"exc_type": getattr(exc_type, "__name__", str(exc_type))},
            )
        except Exception:
            pass
        try:
            if _ORIGINAL_SYS_EXCEPTHOOK is not None:
                _ORIGINAL_SYS_EXCEPTHOOK(exc_type, exc, tb)
        except Exception:
            pass

    sys.excepthook = _sys_excepthook

    try:
        original_threading_hook = getattr(threading, "excepthook", None)

        def _threading_excepthook(args):  # type: ignore[no-untyped-def]
            try:
                write_error_report(
                    args.exc_value,
                    where="threading.excepthook",
                    context={
                        "thread": getattr(args.thread, "name", None),
                        "exc_type": getattr(args.exc_type, "__name__", str(args.exc_type)),
                    },
                )
            except Exception:
                pass
            try:
                if callable(original_threading_hook):
                    original_threading_hook(args)
            except Exception:
                pass

        if original_threading_hook is not None:
            threading.excepthook = _threading_excepthook  # type: ignore[attr-defined]
    except Exception:
        pass

    if enable_faulthandler and faulthandler is not None:
        try:
            global _FAULTHANDLER_FILE
            if _FAULTHANDLER_FILE is None:
                reports_dir = get_error_reports_dir()
                created_at = datetime.now(timezone.utc)
                stamp = created_at.strftime("%Y%m%d_%H%M%S")
                name = f"fatal_{stamp}_{uuid4().hex[:8]}.log"
                path = reports_dir / name
                _FAULTHANDLER_FILE = open(path, "w", encoding="utf-8", errors="replace")

            faulthandler.enable(file=_FAULTHANDLER_FILE, all_threads=True)
        except Exception:
            pass
