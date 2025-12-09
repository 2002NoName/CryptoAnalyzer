"""Sterownik wykorzystujący pytsk3 do pracy z obrazami dysków."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator, List

import pytsk3
from structlog import get_logger

from crypto_analyzer.core.models import DiskSource, FileSystemType, SourceType, Volume
from .base import DataSourceDriver, DriverCapabilities, DriverError


class TskImageDriver:
    """Sterownik bazujący na The Sleuth Kit (pytsk3) dla obrazów dysków."""

    name = "tsk-image"
    capabilities = DriverCapabilities(
        supports_disk_images=True,
        supported_formats=("raw", "img", "dd", "001", "e01", "vhd", "vhdx"),
    )

    def __init__(self, *, image_paths: Iterable[Path] | None = None) -> None:
        self._logger = get_logger(__name__)
        self._image_paths: List[Path] = [Path(path) for path in image_paths] if image_paths else []
        self._img: pytsk3.Img_Info | None = None
        self._volume_info: pytsk3.Volume_Info | None = None
        self._current_source: DiskSource | None = None

    # ------------------------------------------------------------------
    # Implementacja DataSourceDriver
    # ------------------------------------------------------------------

    def enumerate_sources(self) -> Iterator[DiskSource]:
        for path in self._image_paths:
            yield DiskSource(
                identifier=path.name,
                source_type=SourceType.DISK_IMAGE,
                display_name=path.name,
                path=path,
            )

    def open_source(self, source: DiskSource) -> None:
        if source.source_type is not SourceType.DISK_IMAGE:
            raise DriverError("TskImageDriver obsługuje wyłącznie obrazy dysków")
        if source.path is None:
            raise DriverError("Źródło obrazu dysku wymaga ścieżki do pliku")

        self._logger.info("opening-image", path=str(source.path))
        try:
            self._img = pytsk3.Img_Info(str(source.path))
            self._volume_info = pytsk3.Volume_Info(self._img)
            self._current_source = source
        except (OSError, RuntimeError, IOError) as exc:  # pragma: no cover - zależne od środowiska
            self.close()
            raise DriverError(f"Nie udało się otworzyć obrazu dysku: {source.path}") from exc

    def close(self) -> None:
        self._img = None
        self._volume_info = None
        self._current_source = None

    def list_volumes(self) -> Iterator[Volume]:
        if self._volume_info is None or self._current_source is None:
            raise DriverError("Źródło nie zostało otwarte")

        block_size = self._volume_info.info.block_size
        for index, partition in enumerate(self._volume_info, start=1):
            if partition.len <= 0:
                continue  # pomijamy puste partycje

            identifier = f"{self._current_source.identifier}:{index}"
            size_bytes = partition.len * block_size
            offset_bytes = partition.start * block_size

            yield Volume(
                identifier=identifier,
                offset=offset_bytes,
                size=size_bytes,
                filesystem=FileSystemType.UNKNOWN,
            )

    def open_filesystem(self, volume: Volume) -> pytsk3.FS_Info:
        if self._img is None:
            raise DriverError("Brak otwartego źródła obrazu")

        try:
            return pytsk3.FS_Info(self._img, offset=volume.offset)
        except (IOError, RuntimeError) as exc:  # pragma: no cover - zależne od środowiska
            raise DriverError(f"Nie udało się otworzyć systemu plików wolumenu {volume.identifier}") from exc

    def read(self, offset: int, size: int) -> bytes:
        if self._img is None:
            raise DriverError("Brak otwartego źródła obrazu")
        try:
            return self._img.read(offset, size)
        except (IOError, RuntimeError) as exc:  # pragma: no cover - zależne od środowiska
            raise DriverError("Nie udało się odczytać danych z obrazu") from exc


__all__ = ["TskImageDriver"]
