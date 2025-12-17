"""Unit tests for GUI service orchestration (AnalysisService).

These tests avoid native dependencies by patching detector/manager classes.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from crypto_analyzer.core.models import (
    AnalysisResult,
    DiskSource,
    EncryptionStatus,
    FileSystemType,
    SourceType,
    Volume,
)
from crypto_analyzer.ui.services import AnalysisConfig, AnalysisService


@dataclass(slots=True)
class _Finding:
    status: EncryptionStatus
    algorithm: str | None = None
    version: str | None = None
    details: dict | None = None


class _StubDriver:
    def __init__(self, volumes: list[Volume]) -> None:
        self._volumes = volumes
        self.opened = False
        self.closed = False

    def open_source(self, _source: DiskSource) -> None:  # type: ignore[override]
        self.opened = True

    def close(self) -> None:  # type: ignore[override]
        self.closed = True

    def list_volumes(self):  # type: ignore[override]
        return list(self._volumes)


def test_list_volumes_sets_filesystem_and_encryption() -> None:
    svc = AnalysisService()
    source = DiskSource(identifier="img", source_type=SourceType.DISK_IMAGE, display_name="img", path=None)
    volumes = [Volume(identifier="v1", offset=0, size=10, filesystem=FileSystemType.UNKNOWN)]
    driver = _StubDriver(volumes)

    class _FsDet:
        def __init__(self, _driver):
            pass

        def detect(self, _vol: Volume) -> FileSystemType:
            return FileSystemType.NTFS

    class _EncDet:
        def __init__(self, _driver):
            pass

        def analyze_volume(self, _vol: Volume) -> _Finding:
            return _Finding(status=EncryptionStatus.ENCRYPTED, algorithm="bitlocker")

    with (
        patch.object(AnalysisService, "_driver_for_source", return_value=driver),
        patch("crypto_analyzer.ui.services.TskFileSystemDetector", _FsDet),
        patch("crypto_analyzer.ui.services.SignatureBasedDetector", _EncDet),
    ):
        listed = svc.list_volumes(source)

    assert driver.opened is True
    assert driver.closed is True
    assert len(listed) == 1
    assert listed[0].filesystem is FileSystemType.NTFS
    assert listed[0].encryption is EncryptionStatus.ENCRYPTED
    assert listed[0].encryption_algorithm == "bitlocker"


def test_run_analysis_wires_manager_and_closes() -> None:
    svc = AnalysisService()
    source = DiskSource(identifier="img", source_type=SourceType.DISK_IMAGE, display_name="img", path=None)
    base_driver = _StubDriver([Volume(identifier="v1", offset=0, size=10, filesystem=FileSystemType.UNKNOWN)])

    captured: dict[str, object] = {}

    class _FakeManager:
        def __init__(
            self,
            *,
            driver,
            filesystem_detector,
            encryption_detectors,
            metadata_scanner,
            report_exporter,
            progress_reporter,
        ) -> None:
            captured["driver"] = driver
            captured["filesystem_detector"] = filesystem_detector
            captured["encryption_detectors"] = list(encryption_detectors)
            captured["metadata_scanner"] = metadata_scanner
            captured["report_exporter"] = report_exporter
            captured["progress_reporter"] = progress_reporter
            self._closed = False

        def start_session(self, _source: DiskSource):
            return SimpleNamespace(volumes=[Volume(identifier="v1", offset=0, size=10, filesystem=FileSystemType.NTFS)])

        def analyze(self, volume_ids, *, collect_metadata: bool, cancel_event=None):
            captured["volume_ids"] = list(volume_ids)
            captured["collect_metadata"] = collect_metadata
            captured["cancel_event"] = cancel_event
            return AnalysisResult(source=source)

        def close(self) -> None:
            self._closed = True
            captured["closed"] = True

    def _dummy_progress(_msg: str, _pct: int | None) -> None:
        return None

    config = AnalysisConfig(
        source=source,
        selected_volume_ids=["v1"],
        collect_metadata=True,
        metadata_depth=3,
        metadata_workers=4,
    )

    with (
        patch.object(AnalysisService, "_driver_for_source", return_value=base_driver),
        patch("crypto_analyzer.ui.services.AnalysisManager", _FakeManager),
        patch("crypto_analyzer.ui.services.TskFileSystemDetector", lambda d: ("fs", d)),
        patch("crypto_analyzer.ui.services.SignatureBasedDetector", lambda d: ("enc", d)),
        patch("crypto_analyzer.ui.services.TskMetadataScanner", lambda d, max_depth, max_workers: SimpleNamespace(max_depth=max_depth, max_workers=max_workers)),
        patch("crypto_analyzer.ui.services.DefaultReportExporter", lambda: "exporter"),
    ):
        cancel = threading.Event()
        result = svc.run_analysis(config, _dummy_progress, cancel_event=cancel)

    assert isinstance(result, AnalysisResult)
    assert captured.get("closed") is True
    assert captured["volume_ids"] == ["v1"]
    assert captured["collect_metadata"] is True
    assert captured["cancel_event"] is cancel

    # scanner config
    scanner = captured["metadata_scanner"]
    assert getattr(scanner, "max_depth") == 3
    assert getattr(scanner, "max_workers") == 4

    # No unlocking/decryption wrappers are applied.
    assert captured["driver"] is base_driver


def test_run_analysis_closes_base_driver_if_manager_not_created() -> None:
    svc = AnalysisService()
    source = DiskSource(identifier="img", source_type=SourceType.DISK_IMAGE, display_name="img", path=None)
    base_driver = _StubDriver([Volume(identifier="v1", offset=0, size=10, filesystem=FileSystemType.UNKNOWN)])

    config = AnalysisConfig(
        source=source,
        selected_volume_ids=["v1"],
        collect_metadata=False,
        metadata_depth=None,
    )

    def _dummy_progress(_msg: str, _pct: int | None) -> None:
        return None

    # Force failure before manager assignment
    with (
        patch.object(AnalysisService, "_driver_for_source", return_value=base_driver),
        patch.object(AnalysisService, "_open_source", side_effect=RuntimeError("boom")),
    ):
        with pytest.raises(RuntimeError):
            svc.run_analysis(config, _dummy_progress)

    assert base_driver.closed is True
