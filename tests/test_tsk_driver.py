"""Testy jednostkowe dla sterowników TSK."""

from __future__ import annotations

from pathlib import Path

import pytest

from crypto_analyzer.core.models import DiskSource, SourceType
from crypto_analyzer.drivers.base import DriverError
from crypto_analyzer.drivers.tsk import TskPhysicalDiskDriver


def test_physical_driver_enumeration_from_custom_paths(tmp_path: Path) -> None:
    device_a = tmp_path / "disk0"
    device_b = tmp_path / "disk1"

    driver = TskPhysicalDiskDriver(device_paths=[device_a, device_b])
    sources = list(driver.enumerate_sources())

    assert len(sources) == 2
    assert all(source.source_type is SourceType.PHYSICAL_DISK for source in sources)
    assert sources[0].path == device_a
    assert sources[1].path == device_b


def test_physical_driver_rejects_invalid_source_type(tmp_path: Path) -> None:
    driver = TskPhysicalDiskDriver(device_paths=[tmp_path / "disk0"])
    invalid_source = DiskSource(
        identifier="img",
        source_type=SourceType.DISK_IMAGE,
        display_name="Image",
        path=tmp_path / "image.dd",
    )

    with pytest.raises(DriverError):
        driver.open_source(invalid_source)
