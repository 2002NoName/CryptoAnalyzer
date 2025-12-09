"""Interfejs bazowy dla sterowników źródeł danych."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Protocol

from crypto_analyzer.core.models import DiskSource, Volume


class DriverError(RuntimeError):
    """Błąd specyficzny sterowników danych."""


@dataclass(slots=True)
class DriverCapabilities:
    """Opis obsługiwanych funkcji sterownika."""

    supports_physical_disks: bool = False
    supports_disk_images: bool = False
    supported_formats: tuple[str, ...] = ()


class DataSourceDriver(Protocol):
    """Minimalny interfejs dla implementacji sterowników."""

    name: str
    capabilities: DriverCapabilities

    def enumerate_sources(self) -> Iterable[DiskSource]:
        """Zwraca dostępne źródła danych."""

    def open_source(self, source: DiskSource) -> None:
        """Przygotowuje źródło do analizy (tylko do odczytu)."""

    def close(self) -> None:
        """Zwalnia zasoby sterownika."""

    def list_volumes(self) -> Iterable[Volume]:
        """Lista wolumenów dostępnych na otwartym źródle."""

    def open_filesystem(self, volume: Volume) -> Any:
        """Zwraca uchwyt do systemu plików wolumenu (np. pytsk3.FS_Info)."""

    def read(self, offset: int, size: int) -> bytes:
        """Czyta surowe dane z bieżącego źródła."""
