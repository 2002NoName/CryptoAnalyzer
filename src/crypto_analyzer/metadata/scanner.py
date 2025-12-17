"""Interfejs skanera metadanych."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Event
from typing import Callable, Protocol

from crypto_analyzer.core.models import DirectoryNode, Volume


@dataclass(slots=True)
class MetadataResult:
    """Wynik skanowania metadanych."""

    root: DirectoryNode
    total_files: int
    total_directories: int


ProgressCallback = Callable[[int, str | None, str | None], None]


class MetadataScanCancelled(RuntimeError):
    """Sygnalizuje, że skanowanie metadanych zostało anulowane."""


CancelEvent = Event


class MetadataScanner(Protocol):
    """Interfejs dla komponentów zbierających metadane z wolumenów."""

    def scan(
        self,
        volume: Volume,
        *,
        progress: ProgressCallback | None = None,
        cancel_event: CancelEvent | None = None,
    ) -> MetadataResult:
        """Buduje drzewo katalogów wraz z metadanymi."""
