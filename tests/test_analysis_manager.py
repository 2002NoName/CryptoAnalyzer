"""Testy integracji menedżera analizy z detekcją szyfrowania i FS."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

import pytest

from crypto_analyzer.core import AnalysisManager
from crypto_analyzer.core.models import (
    AnalysisResult,
    DiskSource,
    EncryptionStatus,
    FileSystemType,
    SourceType,
    Volume,
)
from crypto_analyzer.crypto_detection import SignatureBasedDetector
from crypto_analyzer.crypto_detection.detectors import EncryptionFinding
from crypto_analyzer.metadata import MetadataScanner
from crypto_analyzer.reporting import ExportFormat, ReportExporter


class StubDriver:
    """Minimalna implementacja sterownika źródła danych na potrzeby testów."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._sources: List[DiskSource] = [
            DiskSource(
                identifier="stub-image",
                source_type=SourceType.DISK_IMAGE,
                display_name="Stub Image",
                path=Path("/tmp/stub.img"),
            )
        ]
        self._opened = False
        self.closed = False
        self._volumes: List[Volume] = [
            Volume(
                identifier="stub-image:1",
                offset=0,
                size=len(data),
                filesystem=FileSystemType.UNKNOWN,
            )
        ]

    def enumerate_sources(self) -> List[DiskSource]:
        return list(self._sources)

    def open_source(self, source: DiskSource) -> None:
        if source not in self._sources:
            raise ValueError("Nieznane źródło")
        self._opened = True

    def close(self) -> None:
        self._opened = False
        self.closed = True

    def list_volumes(self) -> Iterable[Volume]:
        if not self._opened:
            raise RuntimeError("Źródło nie zostało otwarte")
        return list(self._volumes)

    def open_filesystem(self, volume: Volume) -> object:
        if volume not in self._volumes:
            raise ValueError("Nieznany wolumen")
        return object()

    def read(self, offset: int, size: int) -> bytes:
        if not self._opened:
            raise RuntimeError("Źródło nie zostało otwarte")
        return self._data[offset : offset + size]


class StubFileSystemDetector:
    """Prosty detektor zwracający z góry ustalony typ systemu plików."""

    def __init__(self, detected: FileSystemType) -> None:
        self._detected = detected
        self.calls: List[str] = []

    def supported_filesystems(self) -> Iterable[FileSystemType]:
        return [self._detected]

    def detect(self, volume: Volume) -> FileSystemType:
        self.calls.append(volume.identifier)
        return self._detected


class StubMetadataScanner:
    """Skaner metadanych, którego wywołanie w tym teście powinno być pominięte."""

    def scan(self, volume: Volume, *, progress=None):  # type: ignore[override]
        raise AssertionError("Skanowanie metadanych nie powinno być wywołane")


class DummyExporter(ReportExporter):
    """Eksporter zapamiętujący dane wywołania."""

    def __init__(self) -> None:
        self.last_call: tuple[AnalysisResult, Path, ExportFormat] | None = None

    def export(self, result: AnalysisResult, destination: Path, fmt: ExportFormat) -> Path:
        self.last_call = (result, destination, fmt)
        return destination


def test_analysis_manager_integrates_detection(tmp_path) -> None:
    header = b"-FVE-FS-" + b"\x00" * 4088
    driver = StubDriver(header)
    fs_detector = StubFileSystemDetector(FileSystemType.NTFS)
    encryption_detector = SignatureBasedDetector(driver, signature_ids=("bitlocker",))
    metadata_scanner = StubMetadataScanner()
    exporter = DummyExporter()

    manager = AnalysisManager(
        driver=driver,
        filesystem_detector=fs_detector,
        encryption_detectors=[encryption_detector],
        metadata_scanner=metadata_scanner,
        report_exporter=exporter,
    )

    source = driver.enumerate_sources()[0]
    session = manager.start_session(source)
    volume_ids = [volume.identifier for volume in session.volumes]

    result = manager.analyze(volume_ids, collect_metadata=False)

    assert len(result.volumes) == 1
    analysis = result.volumes[0]
    assert analysis.filesystem == FileSystemType.NTFS
    assert analysis.encryption.status == EncryptionStatus.ENCRYPTED
    assert session.volumes[0].filesystem == FileSystemType.NTFS
    assert session.volumes[0].encryption == EncryptionStatus.ENCRYPTED

    destination = tmp_path / "report.json"
    exported_path = manager.export_report(result, destination, ExportFormat.JSON)
    assert exported_path == destination
    assert exporter.last_call is not None
    stored_result, stored_destination, stored_format = exporter.last_call
    assert stored_result is result
    assert stored_destination == destination
    assert stored_format is ExportFormat.JSON

    manager.close()
    assert driver.closed is True


def test_analysis_manager_handles_unknown_filesystem_without_crash(tmp_path) -> None:
    driver = StubDriver(b"")
    fs_detector = StubFileSystemDetector(FileSystemType.UNKNOWN)
    encryption_detector = SignatureBasedDetector(driver, signature_ids=("bitlocker",))
    metadata_scanner = StubMetadataScanner()
    exporter = DummyExporter()

    manager = AnalysisManager(
        driver=driver,
        filesystem_detector=fs_detector,
        encryption_detectors=[encryption_detector],
        metadata_scanner=metadata_scanner,
        report_exporter=exporter,
    )

    source = driver.enumerate_sources()[0]
    session = manager.start_session(source)

    result = manager.analyze([session.volumes[0].identifier], collect_metadata=True)
    assert len(result.volumes) == 1
    analysis = result.volumes[0]
    assert analysis.filesystem is FileSystemType.UNKNOWN
    assert analysis.metadata is None
    manager.close()


def test_analysis_manager_handles_encrypted_unknown_filesystem() -> None:
    driver = StubDriver(b"")
    fs_detector = StubFileSystemDetector(FileSystemType.UNKNOWN)

    class EncryptedDetector:
        def analyze_volume(self, volume: Volume) -> EncryptionFinding:
            return EncryptionFinding(
                status=EncryptionStatus.ENCRYPTED,
                algorithm="BitLocker",
            )

    metadata_scanner = StubMetadataScanner()
    exporter = DummyExporter()

    manager = AnalysisManager(
        driver=driver,
        filesystem_detector=fs_detector,
        encryption_detectors=[EncryptedDetector()],
        metadata_scanner=metadata_scanner,
        report_exporter=exporter,
    )

    source = driver.enumerate_sources()[0]
    session = manager.start_session(source)

    result = manager.analyze([session.volumes[0].identifier], collect_metadata=True)

    assert len(result.volumes) == 1
    analysis = result.volumes[0]
    assert analysis.filesystem is FileSystemType.UNKNOWN
    assert analysis.metadata is None
    assert analysis.encryption.status is EncryptionStatus.ENCRYPTED
    assert session.volumes[0].encryption is EncryptionStatus.ENCRYPTED

    manager.close()
