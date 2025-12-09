"""Heurystyki wykrywania systemów plików."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol

from crypto_analyzer.core.models import FileSystemType, Volume


@dataclass(slots=True)
class FileSystemSignature:
    """Sygnatura systemu plików wykorzystywana podczas detekcji."""

    fs_type: FileSystemType
    description: str


class FileSystemDetector(Protocol):
    """Interfejs dla komponentów wykrywających systemy plików."""

    def supported_filesystems(self) -> Iterable[FileSystemType]:
        """Zwraca obsługiwane typy systemów plików."""

    def detect(self, volume: Volume) -> FileSystemType:
        """Określa typ systemu plików dla podanego wolumenu."""
