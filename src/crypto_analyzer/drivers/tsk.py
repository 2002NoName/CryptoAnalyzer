"""Sterowniki oparte o pytsk3 do pracy z obrazami i dyskami."""

from __future__ import annotations

import json
import os
import platform
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator, List

import pytsk3
from structlog import get_logger

from crypto_analyzer.core.models import DiskSource, FileSystemType, SourceType, Volume
from .base import DriverCapabilities, DriverError


class _BaseTskDriver:
    """Wspólna logika obsługi pytsk3 dla różnych typów źródeł."""

    name = "tsk-base"

    def __init__(self) -> None:
        self._logger = get_logger(__name__)
        self._img: pytsk3.Img_Info | None = None
        self._volume_info: pytsk3.Volume_Info | None = None
        self._current_source: DiskSource | None = None
        self._image_size: int = 0
        self._synthetic_volumes: list[Volume] = []

    # ------------------------------------------------------------------
    # Wspólne operacje
    # ------------------------------------------------------------------

    def _open_with_tsk(self, source: DiskSource, target: Path, *, context: str) -> None:
        self._logger.info("opening-source", driver=self.name, path=str(target))
        try:
            self._img = pytsk3.Img_Info(str(target))
        except (OSError, RuntimeError, IOError) as exc:  # pragma: no cover - zależne od środowiska
            self.close()
            raise DriverError(f"Nie udało się otworzyć {context}: {target}") from exc

        self._image_size = int(self._img.get_size())
        self._current_source = source
        self._synthetic_volumes = []

        try:
            self._volume_info = pytsk3.Volume_Info(self._img)
        except (OSError, RuntimeError, IOError) as exc:  # pragma: no cover - zależne od środowiska
            # W przypadku źródeł bez tablicy partycji wystawiamy syntetyczny wolumen obejmujący całość.
            self._logger.warning(
                "volume-info-unavailable",
                driver=self.name,
                path=str(target),
                error=str(exc),
            )
            self._volume_info = None
            self._synthetic_volumes = [
                Volume(
                    identifier=f"{source.identifier}:0",
                    offset=0,
                    size=self._image_size,
                    filesystem=FileSystemType.UNKNOWN,
                )
            ]

    def close(self) -> None:
        self._img = None
        self._volume_info = None
        self._current_source = None
        self._image_size = 0
        self._synthetic_volumes = []

    def list_volumes(self) -> Iterator[Volume]:
        if self._current_source is None:
            raise DriverError("Źródło nie zostało otwarte")

        if self._volume_info is None:
            yield from self._synthetic_volumes
            return

        block_size = self._volume_info.info.block_size
        for index, partition in enumerate(self._volume_info, start=1):
            if partition.len <= 0:
                continue

            # Skip unallocated / metadata "partitions" returned by TSK.
            # This keeps the UI/CLI and benchmarks focused on real allocated volumes.
            alloc_flag = getattr(pytsk3, "TSK_VS_PART_FLAG_ALLOC", None)
            part_flags = getattr(partition, "flags", None)
            if alloc_flag is not None and isinstance(part_flags, int) and (part_flags & alloc_flag) == 0:
                continue

            yield Volume(
                identifier=f"{self._current_source.identifier}:{index}",
                offset=partition.start * block_size,
                size=partition.len * block_size,
                filesystem=FileSystemType.UNKNOWN,
            )

    def open_filesystem(self, volume: Volume) -> pytsk3.FS_Info:
        if self._img is None:
            raise DriverError("Brak otwartego źródła")
        if self._volume_info is None and volume not in self._synthetic_volumes:
            raise DriverError("Brak informacji o systemie plików dla tego źródła")

        try:
            return pytsk3.FS_Info(self._img, offset=volume.offset)
        except (IOError, RuntimeError) as exc:  # pragma: no cover - zależne od środowiska
            raise DriverError(f"Nie udało się otworzyć systemu plików wolumenu {volume.identifier}") from exc

    def read(self, offset: int, size: int) -> bytes:
        if self._img is None:
            raise DriverError("Brak otwartego źródła")
        try:
            return self._img.read(offset, size)
        except (IOError, RuntimeError) as exc:  # pragma: no cover - zależne od środowiska
            raise DriverError("Nie udało się odczytać danych") from exc


class TskImageDriver(_BaseTskDriver):
    """Sterownik bazujący na The Sleuth Kit (pytsk3) dla obrazów dysków."""

    name = "tsk-image"
    capabilities = DriverCapabilities(
        supports_disk_images=True,
        supported_formats=("raw", "img", "dd", "001", "e01", "vhd", "vhdx"),
    )

    def __init__(self, *, image_paths: Iterable[Path] | None = None) -> None:
        super().__init__()
        self._image_paths: List[Path] = [Path(path) for path in image_paths] if image_paths else []

    # ------------------------------------------------------------------
    # Implementacja DataSourceDriver
    # ------------------------------------------------------------------

    def enumerate_sources(self) -> Iterator[DiskSource]:
        for path in self._image_paths:
            try:
                size_bytes = path.stat().st_size
            except OSError:
                size_bytes = None
            yield DiskSource(
                identifier=path.name,
                source_type=SourceType.DISK_IMAGE,
                display_name=path.name,
                path=path,
                size_bytes=size_bytes,
            )

    def open_source(self, source: DiskSource) -> None:
        if source.source_type is not SourceType.DISK_IMAGE:
            raise DriverError("TskImageDriver obsługuje wyłącznie obrazy dysków")
        if source.path is None:
            raise DriverError("Źródło obrazu dysku wymaga ścieżki do pliku")

        self._open_with_tsk(source, source.path, context="obrazu dysku")


class TskPhysicalDiskDriver(_BaseTskDriver):
    """Sterownik TSK do pracy z dyskami fizycznymi (Windows/Linux/macOS)."""

    name = "tsk-physical"
    capabilities = DriverCapabilities(supports_physical_disks=True)

    def __init__(
        self,
        *,
        device_paths: Iterable[Path | str] | None = None,
        max_devices: int = 32,
    ) -> None:
        super().__init__()
        if device_paths is not None:
            self._sources: List[DiskSource] = [
                DiskSource(
                    identifier=f"physical-{index}",
                    source_type=SourceType.PHYSICAL_DISK,
                    display_name=str(Path(device)),
                    path=Path(device),
                )
                for index, device in enumerate(device_paths)
            ]
        else:
            self._sources = _discover_physical_disks(max_devices=max_devices)

    # ------------------------------------------------------------------
    # Implementacja DataSourceDriver
    # ------------------------------------------------------------------

    def enumerate_sources(self) -> Iterator[DiskSource]:
        yield from self._sources

    def open_source(self, source: DiskSource) -> None:
        if source.source_type is not SourceType.PHYSICAL_DISK:
            raise DriverError("TskPhysicalDiskDriver obsługuje wyłącznie dyski fizyczne")
        if source.path is None:
            raise DriverError("Źródło dysku fizycznego wymaga ścieżki urządzenia")

        self._open_with_tsk(source, source.path, context="dysku fizycznego")


def _discover_physical_disks(*, max_devices: int = 32) -> List[DiskSource]:
    system = platform.system().lower()
    if system == "windows":
        return _discover_windows_disks(max_devices=max_devices)
    if system == "linux":
        return _discover_linux_disks()
    if system == "darwin":
        return _discover_macos_disks()
    return []


def _discover_windows_disks(*, max_devices: int) -> List[DiskSource]:  # pragma: no cover - zależne od OS
    disks: List[DiskSource] = []
    disk_info = _windows_disk_info()
    for index in range(max_devices):
        raw_path = f"\\\\.\\PhysicalDrive{index}"
        exists, accessible = _probe_device_open(raw_path)
        if not exists:
            continue

        info = disk_info.get(index, {})
        model = info.get("model") if isinstance(info, dict) else None
        size_bytes = info.get("size") if isinstance(info, dict) else None

        display = model or f"Physical Drive {index}"
        if not accessible:
            display += " (access denied - run as administrator)"

        disks.append(
            DiskSource(
                identifier=f"physical{index}",
                source_type=SourceType.PHYSICAL_DISK,
                display_name=display,
                path=Path(raw_path),
                size_bytes=size_bytes,
            )
        )
    return disks


def _discover_linux_disks() -> List[DiskSource]:  # pragma: no cover - zależne od OS
    disks: List[DiskSource] = []
    block_dir = Path("/sys/block")
    candidates: list[Path] = []
    if block_dir.exists():
        for entry in sorted(block_dir.iterdir()):
            name = entry.name
            if any(
                name.startswith(prefix)
                for prefix in ("loop", "ram", "fd", "sr", "dm-", "nbd", "zd")
            ):
                continue
            device = Path("/dev") / name
            if device.exists():
                candidates.append(device)

    if not candidates:
        candidates.extend(Path("/dev").glob("sd?"))
        candidates.extend(Path("/dev").glob("nvme?n?"))
        candidates.extend(Path("/dev").glob("vd?"))

    seen: set[Path] = set()
    for device in candidates:
        if device in seen:
            continue
        seen.add(device)

        exists, accessible = _probe_device_open(str(device))
        if not exists:
            continue

        display = device.as_posix()
        if not accessible:
            display += " (brak dostępu)"

        disks.append(
            DiskSource(
                identifier=device.name,
                source_type=SourceType.PHYSICAL_DISK,
                display_name=display,
                path=device,
                size_bytes=_linux_disk_size(device),
            )
        )

    return disks


def _discover_macos_disks() -> List[DiskSource]:  # pragma: no cover - zależne od OS
    disks: List[DiskSource] = []
    candidates = sorted(Path("/dev").glob("disk[0-9]"))
    for device in candidates:
        exists, accessible = _probe_device_open(str(device))
        if not exists:
            continue

        display = device.as_posix()
        if not accessible:
            display += " (brak dostępu)"

        disks.append(
            DiskSource(
                identifier=device.name,
                source_type=SourceType.PHYSICAL_DISK,
                display_name=display,
                path=device,
            )
        )
    return disks


def _probe_device_open(device_path: str) -> tuple[bool, bool]:
    """Sprawdza, czy urządzenie istnieje i czy mamy do niego dostęp."""

    flags = os.O_RDONLY
    binary_flag = getattr(os, "O_BINARY", 0)
    if binary_flag:
        flags |= binary_flag

    try:
        fd = os.open(device_path, flags)
    except FileNotFoundError:
        return False, False
    except PermissionError:
        return True, False
    except OSError as exc:
        # Niektóre błędy wskazują na istniejące urządzenie, ale brak uprawnień (np. ERROR_ACCESS_DENIED).
        if getattr(exc, "winerror", None) in {5, 32, 1117}:
            return True, False
        if exc.errno in {5, 13, 16, 30}:
            return True, False
        return False, False
    else:
        os.close(fd)
        return True, True


def _linux_disk_size(device: Path) -> int | None:  # pragma: no cover - zależne od OS
    size_file = Path("/sys/block") / device.name / "size"
    try:
        sectors = int(size_file.read_text().strip())
    except (FileNotFoundError, ValueError, OSError):
        return None
    # Linux raportuje liczbę sektorów 512-bajtowych
    return sectors * 512


__all__ = ["TskImageDriver", "TskPhysicalDiskDriver"]


@lru_cache(maxsize=1)
def _windows_disk_info() -> dict[int, dict[str, int | str]]:  # pragma: no cover - zależne od OS
    if platform.system().lower() != "windows":
        return {}

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-CimInstance -ClassName Win32_DiskDrive "
                    "| Select-Object Index,Model,Size "
                    "| ConvertTo-Json -Compress"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return {}

    raw_output = result.stdout.strip()
    if not raw_output:
        return {}

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return {}

    entries = data if isinstance(data, list) else [data]
    mapping: dict[int, dict[str, int | str]] = {}
    for entry in entries:
        try:
            index = int(entry.get("Index"))
        except (TypeError, ValueError):
            continue
        model = str(entry.get("Model")) if entry.get("Model") else ""
        size_value = entry.get("Size")
        size_int: int | None
        try:
            size_int = int(size_value) if size_value is not None else None
        except (TypeError, ValueError):
            size_int = None

        record: dict[str, int | str] = {}
        if model:
            record["model"] = model.strip()
        if size_int is not None:
            record["size"] = size_int
        if record:
            mapping[index] = record
    return mapping
