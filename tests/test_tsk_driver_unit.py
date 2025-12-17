"""Pure unit tests for the TSK driver module.

These tests monkeypatch pytsk3 classes so they don't require the real TSK
bindings or actual disk images.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from crypto_analyzer.core.models import DiskSource, FileSystemType, SourceType
from crypto_analyzer.drivers.base import DriverError
from crypto_analyzer.drivers.tsk import TskImageDriver


def test_tsk_image_driver_rejects_missing_path() -> None:
    driver = TskImageDriver(image_paths=[])
    source = DiskSource(identifier="img", source_type=SourceType.DISK_IMAGE, display_name="img", path=None)

    with pytest.raises(DriverError):
        driver.open_source(source)


def test_tsk_image_driver_lists_synthetic_volume_when_volume_info_unavailable(monkeypatch, tmp_path: Path) -> None:
    image = tmp_path / "a.img"
    image.write_bytes(b"x" * 1234)

    # Patch pytsk3 so Volume_Info raises (simulates images without partition table)
    import crypto_analyzer.drivers.tsk as tsk_mod

    class _Img:
        def __init__(self, _path: str):
            self._path = _path

        def get_size(self) -> int:
            return 1234

        def read(self, _offset: int, size: int) -> bytes:
            return b"\x00" * int(size)

    class _VolumeInfo:
        def __init__(self, _img):
            raise RuntimeError("no partition table")

    monkeypatch.setattr(tsk_mod.pytsk3, "Img_Info", _Img)
    monkeypatch.setattr(tsk_mod.pytsk3, "Volume_Info", _VolumeInfo)

    driver = TskImageDriver(image_paths=[image])
    source = next(driver.enumerate_sources())

    driver.open_source(source)
    volumes = list(driver.list_volumes())

    assert len(volumes) == 1
    assert volumes[0].identifier.endswith(":0")
    assert volumes[0].offset == 0
    assert volumes[0].size == 1234
    assert volumes[0].filesystem is FileSystemType.UNKNOWN


def test_tsk_image_driver_lists_partition_volumes(monkeypatch, tmp_path: Path) -> None:
    image = tmp_path / "b.img"
    image.write_bytes(b"x" * 4096)

    import crypto_analyzer.drivers.tsk as tsk_mod

    class _Img:
        def __init__(self, _path: str):
            self._path = _path

        def get_size(self) -> int:
            return 4096

        def read(self, _offset: int, size: int) -> bytes:
            return b"\x00" * int(size)

    class _Partition:
        def __init__(self, start: int, length: int):
            self.start = start
            self.len = length

    class _VolInfoInfo:
        block_size = 512

    class _VolumeInfo:
        def __init__(self, _img):
            self.info = _VolInfoInfo()
            self._parts = [_Partition(1, 2), _Partition(10, 0), _Partition(20, 1)]

        def __iter__(self):
            return iter(self._parts)

    monkeypatch.setattr(tsk_mod.pytsk3, "Img_Info", _Img)
    monkeypatch.setattr(tsk_mod.pytsk3, "Volume_Info", _VolumeInfo)

    driver = TskImageDriver(image_paths=[image])
    source = next(driver.enumerate_sources())
    driver.open_source(source)

    volumes = list(driver.list_volumes())
    # skips len<=0 partition
    assert [v.offset for v in volumes] == [1 * 512, 20 * 512]
    assert [v.size for v in volumes] == [2 * 512, 1 * 512]
    assert volumes[0].identifier.endswith(":1")
    assert volumes[1].identifier.endswith(":3")  # enumerate start=1, includes skipped partition index


def test_tsk_image_driver_open_filesystem_passes_offset(monkeypatch, tmp_path: Path) -> None:
    image = tmp_path / "c.img"
    image.write_bytes(b"x" * 2048)

    import crypto_analyzer.drivers.tsk as tsk_mod

    class _Img:
        def __init__(self, _path: str):
            self._path = _path

        def get_size(self) -> int:
            return 2048

        def read(self, _offset: int, size: int) -> bytes:
            return b"\x00" * int(size)

    class _VolInfoInfo:
        block_size = 512

    class _VolumeInfo:
        def __init__(self, _img):
            self.info = _VolInfoInfo()
            self._parts = []

        def __iter__(self):
            return iter(self._parts)

    captured: dict[str, int] = {}

    class _FS:
        def __init__(self, _img, *, offset: int = 0):
            captured["offset"] = int(offset)

    monkeypatch.setattr(tsk_mod.pytsk3, "Img_Info", _Img)
    monkeypatch.setattr(tsk_mod.pytsk3, "Volume_Info", _VolumeInfo)
    monkeypatch.setattr(tsk_mod.pytsk3, "FS_Info", _FS)

    driver = TskImageDriver(image_paths=[image])
    source = next(driver.enumerate_sources())
    driver.open_source(source)

    # Synthetic volumes won't exist because Volume_Info doesn't throw; use direct Volume.
    from crypto_analyzer.core.models import Volume

    vol = Volume(identifier="img:1", offset=123, size=10, filesystem=FileSystemType.UNKNOWN)
    driver.open_filesystem(vol)
    assert captured["offset"] == 123
