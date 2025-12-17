"""Additional unit tests for AnalysisManager internals and edge cases."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

import pytest

from crypto_analyzer.core.analysis_manager import AnalysisCancelledError, AnalysisManager
from crypto_analyzer.core.models import (
    AnalysisResult,
    DiskSource,
    EncryptionStatus,
    FileSystemType,
    SourceType,
    Volume,
)
from crypto_analyzer.crypto_detection.detectors import EncryptionFinding
from crypto_analyzer.reporting import ExportFormat, ReportExporter


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

    def open_filesystem(self, _volume: Volume):  # type: ignore[override]
        return object()


class _FsDet:
    def __init__(self, fs: FileSystemType) -> None:
        self._fs = fs

    def supported_filesystems(self):
        return [self._fs]

    def detect(self, _volume: Volume) -> FileSystemType:
        return self._fs


class _NoopMetadataScanner:
    def __init__(self) -> None:
        self.called = False

    def scan(self, _volume: Volume, *, progress=None, cancel_event=None):  # type: ignore[override]
        self.called = True
        return None


@dataclass(slots=True)
class _DummyExporter(ReportExporter):
    called: bool = False

    def export(self, result: AnalysisResult, destination: Path, fmt: ExportFormat) -> Path:
        self.called = True
        return destination


def test_analyze_raises_cancelled_when_event_set() -> None:
    vol = Volume(identifier="v1", offset=0, size=1, filesystem=FileSystemType.UNKNOWN)
    driver = _StubDriver([vol])

    class _EncDet:
        def analyze_volume(self, _v: Volume) -> EncryptionFinding:
            return EncryptionFinding(status=EncryptionStatus.UNKNOWN)

    manager = AnalysisManager(
        driver=driver,
        filesystem_detector=_FsDet(FileSystemType.NTFS),
        encryption_detectors=[_EncDet()],
        metadata_scanner=_NoopMetadataScanner(),
        report_exporter=_DummyExporter(),
    )

    source = DiskSource(identifier="img", source_type=SourceType.DISK_IMAGE, display_name="img", path=Path("/tmp/a"))
    manager.start_session(source)

    cancel = threading.Event()
    cancel.set()
    with pytest.raises(AnalysisCancelledError):
        manager.analyze(["v1"], collect_metadata=False, cancel_event=cancel)


def test_encryption_detector_fallback_picks_first_non_unknown() -> None:
    vol = Volume(identifier="v1", offset=0, size=1, filesystem=FileSystemType.UNKNOWN)
    driver = _StubDriver([vol])

    class _UnknownDet:
        def analyze_volume(self, _v: Volume) -> EncryptionFinding:
            return EncryptionFinding(status=EncryptionStatus.UNKNOWN)

    class _EncryptedDet:
        def analyze_volume(self, _v: Volume) -> EncryptionFinding:
            return EncryptionFinding(status=EncryptionStatus.ENCRYPTED, algorithm="BitLocker")

    manager = AnalysisManager(
        driver=driver,
        filesystem_detector=_FsDet(FileSystemType.NTFS),
        encryption_detectors=[_UnknownDet(), _EncryptedDet()],
        metadata_scanner=_NoopMetadataScanner(),
        report_exporter=_DummyExporter(),
    )

    source = DiskSource(identifier="img", source_type=SourceType.DISK_IMAGE, display_name="img", path=Path("/tmp/a"))
    session = manager.start_session(source)

    result = manager.analyze([session.volumes[0].identifier], collect_metadata=False)

    assert result.volumes[0].encryption.status is EncryptionStatus.ENCRYPTED
    assert session.volumes[0].encryption is EncryptionStatus.ENCRYPTED


def test_format_metadata_detail() -> None:
    assert AnalysisManager._format_metadata_detail("directory", "/a") == "Katalog: /a"
    assert AnalysisManager._format_metadata_detail("file", "/a/b") == "Plik: /a/b"
    assert AnalysisManager._format_metadata_detail("other", "/x") == "/x"
    assert AnalysisManager._format_metadata_detail("file", None) is None
