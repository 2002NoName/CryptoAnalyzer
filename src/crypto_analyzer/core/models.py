"""Modele danych używane w rdzeniu aplikacji."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Iterable, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from crypto_analyzer.crypto_detection.detectors import EncryptionFinding
    from crypto_analyzer.metadata.scanner import MetadataResult


class SourceType(str, Enum):
    """Rodzaj analizowanego źródła danych."""

    PHYSICAL_DISK = "physical_disk"
    DISK_IMAGE = "disk_image"


class FileSystemType(str, Enum):
    """Obsługiwane systemy plików."""

    NTFS = "ntfs"
    EXT4 = "ext4"
    FAT32 = "fat32"
    APFS = "apfs"
    UNKNOWN = "unknown"


class EncryptionStatus(str, Enum):
    """Status wykrytego szyfrowania."""

    NOT_DETECTED = "not_detected"
    ENCRYPTED = "encrypted"
    PARTIALLY_ENCRYPTED = "partially_encrypted"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class DiskSource:
    """Opis źródła danych (dysk fizyczny lub obraz)."""

    identifier: str
    source_type: SourceType
    display_name: str
    path: Optional[Path] = None


@dataclass(slots=True)
class Volume:
    """Model wolumenu wykrytego na źródle danych."""

    identifier: str
    offset: int
    size: int
    filesystem: FileSystemType
    encryption: EncryptionStatus = EncryptionStatus.UNKNOWN


@dataclass(slots=True)
class FileMetadata:
    """Metadane pojedynczego pliku."""

    name: str
    path: PurePosixPath
    size: int
    owner: Optional[str]
    created_at: Optional[str]
    modified_at: Optional[str]
    accessed_at: Optional[str]
    encryption: EncryptionStatus = EncryptionStatus.UNKNOWN


@dataclass(slots=True)
class DirectoryNode:
    """Węzeł drzewa katalogów."""

    name: str
    path: PurePosixPath
    files: List[FileMetadata] = field(default_factory=list)
    subdirectories: List["DirectoryNode"] = field(default_factory=list)

    def iter_files(self) -> Iterable[FileMetadata]:
        """Iteruje po wszystkich plikach w węźle (rekurencyjnie)."""

        yield from self.files
        for subdirectory in self.subdirectories:
            yield from subdirectory.iter_files()


@dataclass(slots=True)
class VolumeAnalysis:
    """Wynik analizy pojedynczego wolumenu."""

    volume: Volume
    filesystem: FileSystemType
    encryption: "EncryptionFinding"
    metadata: "MetadataResult | None" = None


@dataclass(slots=True)
class AnalysisResult:
    """Podsumowanie całej analizy źródła danych."""

    source: DiskSource
    volumes: List[VolumeAnalysis] = field(default_factory=list)

    def total_files(self) -> int:
        """Łączna liczba plików w analizie."""

        return sum(volume.metadata.total_files for volume in self.volumes if volume.metadata)

    def total_directories(self) -> int:
        """Łączna liczba katalogów w analizie."""

        return sum(volume.metadata.total_directories for volume in self.volumes if volume.metadata)
