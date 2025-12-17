"""Extra unit tests for the TSK filesystem detector edge cases."""

from __future__ import annotations

import pytest

from crypto_analyzer.core.models import FileSystemType, Volume
from crypto_analyzer.drivers.base import DriverError
from crypto_analyzer.fs_detection.tsk import TskFileSystemDetector


def test_tsk_detector_bitmask_fallback() -> None:
    import pytsk3

    # ftype is not exactly equal to NTFS constant, but includes it as a bit.
    ftype = int(pytsk3.TSK_FS_TYPE_NTFS) | 0x40000000

    class _StubDriver:
        def open_filesystem(self, _volume: Volume):  # type: ignore[override]
            class _Info:
                def __init__(self, ftype: int) -> None:
                    self.ftype = ftype

            class _FS:
                def __init__(self, ftype: int) -> None:
                    self.info = _Info(ftype)

            return _FS(ftype)

    detector = TskFileSystemDetector(_StubDriver())
    volume = Volume(identifier="v1", offset=0, size=0, filesystem=FileSystemType.UNKNOWN)

    assert detector.detect(volume) is FileSystemType.NTFS


def test_tsk_detector_returns_unknown_when_driver_raises() -> None:
    class _StubDriver:
        def open_filesystem(self, _volume: Volume):  # type: ignore[override]
            raise DriverError("boom")

    detector = TskFileSystemDetector(_StubDriver())
    volume = Volume(identifier="v1", offset=0, size=0, filesystem=FileSystemType.UNKNOWN)

    assert detector.detect(volume) is FileSystemType.UNKNOWN
