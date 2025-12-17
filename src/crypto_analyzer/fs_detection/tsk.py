"""Detekcja systemów plików z wykorzystaniem pytsk3."""

from __future__ import annotations

from typing import Iterable, Tuple

import pytsk3

from crypto_analyzer.core.models import FileSystemType, Volume
from crypto_analyzer.drivers import DataSourceDriver, DriverError
from .detector import FileSystemDetector


_FS_TYPE_MAP: Tuple[Tuple[int, FileSystemType], ...] = (
    (pytsk3.TSK_FS_TYPE_NTFS, FileSystemType.NTFS),
    (pytsk3.TSK_FS_TYPE_EXT2, FileSystemType.EXT2),
    (pytsk3.TSK_FS_TYPE_EXT3, FileSystemType.EXT3),
    (pytsk3.TSK_FS_TYPE_EXT4, FileSystemType.EXT4),
    (pytsk3.TSK_FS_TYPE_FAT12, FileSystemType.FAT12),
    (pytsk3.TSK_FS_TYPE_FAT16, FileSystemType.FAT16),
    (pytsk3.TSK_FS_TYPE_FAT32, FileSystemType.FAT32),
    (pytsk3.TSK_FS_TYPE_EXFAT, FileSystemType.EXFAT),
    (pytsk3.TSK_FS_TYPE_APFS, FileSystemType.APFS),
    (pytsk3.TSK_FS_TYPE_HFS, FileSystemType.HFS_PLUS),
    (pytsk3.TSK_FS_TYPE_ISO9660, FileSystemType.ISO9660),
    (pytsk3.TSK_FS_TYPE_FFS1, FileSystemType.UFS),
    (pytsk3.TSK_FS_TYPE_FFS1B, FileSystemType.UFS),
    (pytsk3.TSK_FS_TYPE_FFS2, FileSystemType.UFS),
)


class TskFileSystemDetector(FileSystemDetector):
    """Implementacja detektora systemów plików oparta na pytsk3."""

    def __init__(self, driver: DataSourceDriver) -> None:
        self._driver = driver

    def supported_filesystems(self) -> Iterable[FileSystemType]:
        return tuple(fs_type for _, fs_type in _FS_TYPE_MAP)

    def detect(self, volume: Volume) -> FileSystemType:
        try:
            fs_handle = self._driver.open_filesystem(volume)
        except DriverError:
            return FileSystemType.UNKNOWN

        fs_type_code = fs_handle.info.ftype
        # Najpierw porównujemy dokładne wartości stałych TSK.
        for mask, fs_type in _FS_TYPE_MAP:
            if fs_type_code == mask:
                return fs_type

        # Jeżeli pytsk3 zwróci kombinację masek (np. *_DETECT), wykonujemy
        # dopasowanie bitowe jako zapasowe rozwiązanie.
        for mask, fs_type in _FS_TYPE_MAP:
            if fs_type_code & mask:
                return fs_type

        return FileSystemType.UNKNOWN


__all__ = ["TskFileSystemDetector"]
