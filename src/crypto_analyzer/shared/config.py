"""Konfiguracja aplikacji."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class AppConfig:
    """Konfiguracja ogólna aplikacji."""

    workspace_dir: Path
    enable_telemetry: bool = False

    @classmethod
    def default(cls) -> "AppConfig":
        """Tworzy domyślną konfigurację."""

        return cls(workspace_dir=Path.cwd())
