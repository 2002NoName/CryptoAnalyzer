"""Warstwa usługowa udostępniająca operacje analizy dla GUI."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, List, Sequence

from crypto_analyzer.core import AnalysisManager
from crypto_analyzer.core.models import (
    AnalysisResult,
    DiskSource,
    EncryptionStatus,
    FileSystemType,
    SourceType,
    Volume,
)
from crypto_analyzer.crypto_detection import HeuristicEncryptionDetector, SignatureBasedDetector
from crypto_analyzer.drivers import (
    DataSourceDriver,
    DriverError,
    TskImageDriver,
    TskPhysicalDiskDriver,
)
from crypto_analyzer.fs_detection import TskFileSystemDetector
from crypto_analyzer.metadata import TskMetadataScanner
from crypto_analyzer.reporting import DefaultReportExporter
from crypto_analyzer.shared import configure_logging


ProgressCallback = Callable[[str, int | None], None]


@dataclass(slots=True)
class AnalysisConfig:
    source: DiskSource
    selected_volume_ids: Sequence[str]
    collect_metadata: bool
    metadata_depth: int | None
    metadata_workers: int = 1


class _SignalProgressReporter:
    """Mostkowy reporter postępu przekazujący zdarzenia do callbacku."""

    def __init__(self, callback: ProgressCallback) -> None:
        self._callback = callback

    def update(self, message: str, *, percentage: int | None = None) -> None:
        self._callback(message, percentage)


class AnalysisService:
    """Udostępnia operacje przygotowania i wykonania analizy dla GUI."""

    def __init__(self) -> None:
        configure_logging()

    def list_physical_sources(self) -> List[DiskSource]:
        driver = TskPhysicalDiskDriver()
        try:
            return list(driver.enumerate_sources())
        finally:
            driver.close()

    def create_image_source(self, image_path: Path) -> DiskSource:
        try:
            size_bytes = image_path.stat().st_size
        except OSError:
            size_bytes = None
        return DiskSource(
            identifier=image_path.name,
            source_type=SourceType.DISK_IMAGE,
            display_name=image_path.name,
            path=image_path,
            size_bytes=size_bytes,
        )

    def list_volumes(self, source: DiskSource) -> List[Volume]:
        driver = self._driver_for_source(source)
        try:
            self._open_source(driver, source)
            volumes = list(driver.list_volumes())
            try:
                fs_detector = TskFileSystemDetector(driver)
            except Exception:
                return volumes

            try:
                encryption_detectors = [SignatureBasedDetector(driver), HeuristicEncryptionDetector(driver)]
            except Exception:
                encryption_detectors = []

            for volume in volumes:
                try:
                    fs_type = fs_detector.detect(volume)
                except Exception:
                    fs_type = FileSystemType.UNKNOWN
                volume.filesystem = fs_type

                if not encryption_detectors:
                    continue

                for detector in encryption_detectors:
                    try:
                        finding = detector.analyze_volume(volume)
                    except Exception:
                        continue

                    if finding.status in {EncryptionStatus.ENCRYPTED, EncryptionStatus.PARTIALLY_ENCRYPTED}:
                        volume.encryption = finding.status
                        volume.encryption_algorithm = finding.algorithm
                        break

                    if volume.encryption is EncryptionStatus.UNKNOWN and finding.status is not EncryptionStatus.UNKNOWN:
                        volume.encryption = finding.status
                        volume.encryption_algorithm = finding.algorithm
            return volumes
        finally:
            driver.close()

    def run_analysis(
        self,
        config: AnalysisConfig,
        progress: ProgressCallback,
        *,
        cancel_event: threading.Event | None = None,
    ) -> AnalysisResult:
        base_driver = self._driver_for_source(config.source)
        reporter = _SignalProgressReporter(progress)
        manager: AnalysisManager | None = None

        try:
            self._open_source(base_driver, config.source)
            driver: DataSourceDriver = base_driver

            manager = AnalysisManager(
                driver=driver,
                filesystem_detector=TskFileSystemDetector(driver),
                encryption_detectors=[SignatureBasedDetector(driver), HeuristicEncryptionDetector(driver)],
                metadata_scanner=TskMetadataScanner(
                    driver,
                    max_depth=config.metadata_depth if config.collect_metadata else None,
                    max_workers=config.metadata_workers if config.collect_metadata else 1,
                ),
                report_exporter=DefaultReportExporter(),
                progress_reporter=reporter,
            )

            session = manager.start_session(config.source)
            if not session.volumes:
                raise RuntimeError("Brak wolumenów do analizy")

            result = manager.analyze(
                config.selected_volume_ids,
                collect_metadata=config.collect_metadata,
                cancel_event=cancel_event,
            )
            return result
        finally:
            if manager is not None:
                manager.close()
            else:
                base_driver.close()

    def _driver_for_source(self, source: DiskSource) -> DataSourceDriver:
        if source.source_type is SourceType.DISK_IMAGE:
            if source.path is None:
                raise DriverError("Obraz dysku wymaga ścieżki")
            return TskImageDriver(image_paths=[source.path])
        if source.path is None:
            raise DriverError("Dysk fizyczny wymaga ścieżki urządzenia")
        return TskPhysicalDiskDriver(device_paths=[source.path])

    def _open_source(self, driver: DataSourceDriver, source: DiskSource) -> None:
        driver.open_source(source)


__all__ = ["AnalysisConfig", "AnalysisService"]
