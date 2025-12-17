"""Testy dla detektora systemów plików opartego o pytsk3."""

from __future__ import annotations

import pytsk3
import pytest

from crypto_analyzer.core.models import FileSystemType, Volume
from crypto_analyzer.fs_detection.tsk import TskFileSystemDetector


class _StubDriver:
    """Sterownik zwracający przygotowaną instancję FS_Info."""

    def __init__(self, ftype: int) -> None:
        self._ftype = ftype

    def open_filesystem(self, volume: Volume):  # type: ignore[override]
        class _Info:
            def __init__(self, ftype: int) -> None:
                self.ftype = ftype

        class _FSInfo:
            def __init__(self, ftype: int) -> None:
                self.info = _Info(ftype)

        return _FSInfo(self._ftype)


@pytest.mark.parametrize(
    ("mask", "expected"),
    [
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
    ],
)
def test_tsk_detector_maps_known_filesystems(mask: int, expected: FileSystemType) -> None:
    detector = TskFileSystemDetector(_StubDriver(mask))
    volume = Volume(identifier="v1", offset=0, size=0, filesystem=FileSystemType.UNKNOWN)

    detected = detector.detect(volume)

    assert detected is expected


def test_tsk_detector_supported_filesystems_matches_map() -> None:
    detector = TskFileSystemDetector(_StubDriver(pytsk3.TSK_FS_TYPE_NTFS))
    supported = set(detector.supported_filesystems())

    assert FileSystemType.UNKNOWN not in supported
    # Sprawdzamy czy wszystkie wartości poza UNKNOWN zostały zgłoszone.
    expected = {fs for fs in FileSystemType if fs is not FileSystemType.UNKNOWN}
    assert supported == expected