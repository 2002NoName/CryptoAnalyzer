"""Unit tests for unlocking driver wrappers.

These focus on pure-Python behavior (bounded file views and best-effort fallback)
and do not require native crypto bindings.
"""

from __future__ import annotations

from dataclasses import dataclass

from crypto_analyzer.core.models import FileSystemType, Volume
from crypto_analyzer.drivers.bitlocker import BitLockerUnlockingDriver, _BoundedFileView as BdeView
from crypto_analyzer.drivers.filevault2 import FileVault2UnlockingDriver, _BoundedFileView as FvdeView


@dataclass(slots=True)
class _ReadSpyDriver:
    data: bytes

    def read(self, offset: int, size: int) -> bytes:  # type: ignore[override]
        offset = int(offset)
        size = int(size)
        return self.data[offset : offset + size]

    def open_filesystem(self, volume: Volume):  # type: ignore[override]
        return ("fs", volume.identifier)

    def enumerate_sources(self):  # pragma: no cover
        return ()

    def open_source(self, _source):  # pragma: no cover
        return None

    def close(self):  # pragma: no cover
        return None

    def list_volumes(self):  # pragma: no cover
        return ()


def test_bounded_file_view_read_seek_bitlocker() -> None:
    driver = _ReadSpyDriver(data=b"abcdefghijklmnopqrstuvwxyz")
    view = BdeView(driver=driver, base_offset=5, size=10)  # f..o

    assert view.read(3) == b"fgh"
    assert view.tell() == 3

    view.seek(0)
    assert view.read() == b"fghijklmno"

    view.seek(-2, 2)  # from end
    assert view.read(10) == b"no"


def test_bounded_file_view_read_seek_filevault2() -> None:
    driver = _ReadSpyDriver(data=b"0123456789")
    view = FvdeView(driver=driver, base_offset=2, size=5)  # 2..6

    assert view.read(2) == b"23"
    view.seek(1, 1)
    assert view.read(10) == b"56"  # clamped to remaining bytes


def test_unlocking_drivers_fallback_when_bindings_missing() -> None:
    wrapped = _ReadSpyDriver(data=b"x" * 1024)
    vol = Volume(identifier="vol1", offset=0, size=1024, filesystem=FileSystemType.NTFS)

    bde = BitLockerUnlockingDriver(wrapped, recovery_keys={"vol1": "123"})
    assert bde.open_filesystem(vol) == ("fs", "vol1")

    fvde = FileVault2UnlockingDriver(wrapped, passwords={"vol1": "pw"})
    assert fvde.open_filesystem(vol) == ("fs", "vol1")
