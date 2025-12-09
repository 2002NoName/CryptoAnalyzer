"""Interfejs skanera metadanych."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from crypto_analyzer.core.models import DirectoryNode, Volume


@dataclass(slots=True)
class MetadataResult:
    """Wynik skanowania metadanych."""

    root: DirectoryNode
    total_files: int
    total_directories: int


class MetadataScanner(Protocol):
    """Interfejs dla komponentów zbierających metadane z wolumenów."""

    def scan(self, volume: Volume) -> MetadataResult:
        """Buduje drzewo katalogów wraz z metadanymi."""
