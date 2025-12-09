"""Zarządzanie pełnym cyklem analizy źródła danych."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

import structlog
from structlog.stdlib import BoundLogger

from crypto_analyzer.core.models import (
    AnalysisResult,
    DiskSource,
    EncryptionStatus,
    FileSystemType,
    Volume,
    VolumeAnalysis,
)
from crypto_analyzer.crypto_detection import EncryptionDetector, EncryptionFinding
from crypto_analyzer.fs_detection import FileSystemDetector
from crypto_analyzer.drivers import DataSourceDriver
from crypto_analyzer.metadata import MetadataResult, MetadataScanner
from crypto_analyzer.reporting import ExportFormat, ReportExporter
from .session import AnalysisSession
from .tasks import ProgressReporter


@dataclass
class DefaultProgressReporter:
    """Prosty reporter postępu logujący zdarzenia do konsoli."""

    logger: BoundLogger = field(default_factory=lambda: structlog.get_logger(__name__))

    def update(self, message: str, *, percentage: int | None = None) -> None:
        if percentage is not None:
            self.logger.info("progress", message=message, percentage=percentage)
        else:
            self.logger.info("progress", message=message)


class AnalysisManager:
    """Orkiestrator analizujący źródło danych przy użyciu dostarczonych komponentów."""

    def __init__(
        self,
        *,
        driver: DataSourceDriver,
        filesystem_detector: FileSystemDetector,
        encryption_detectors: Iterable[EncryptionDetector],
        metadata_scanner: MetadataScanner,
        report_exporter: ReportExporter,
        progress_reporter: ProgressReporter | None = None,
    ) -> None:
        self._driver = driver
        self._filesystem_detector = filesystem_detector
        self._encryption_detectors = list(encryption_detectors)
        self._metadata_scanner = metadata_scanner
        self._report_exporter = report_exporter
        self._progress_reporter = progress_reporter or DefaultProgressReporter()
        self._logger = structlog.get_logger(__name__)
        self._session: AnalysisSession | None = None

    # ------------------------------------------------------------------
    # Zarządzanie sesją
    # ------------------------------------------------------------------

    def start_session(self, source: DiskSource) -> AnalysisSession:
        """Inicjuje sesję analizy dla wskazanego źródła."""

        self._progress("Inicjalizacja sesji", percentage=5)
        self._driver.open_source(source)
        volumes = list(self._driver.list_volumes())
        self._session = AnalysisSession(source=source, volumes=volumes)
        self._progress(f"Wykryto {len(volumes)} wolumen(y)", percentage=15)
        return self._session

    def session(self) -> AnalysisSession:
        """Zwraca aktywną sesję lub zgłasza błąd, jeśli brak."""

        if self._session is None:
            raise RuntimeError("Sesja analizy nie została zainicjalizowana")
        return self._session

    def close(self) -> None:
        """Kończy pracę z bieżącym sterownikiem."""

        self._driver.close()
        self._session = None

    # ------------------------------------------------------------------
    # Analiza
    # ------------------------------------------------------------------

    def analyze(self, volume_ids: Sequence[str], *, collect_metadata: bool = True) -> AnalysisResult:
        """Analizuje wybrane wolumeny i zwraca wyniki."""

        session = self.session()
        selected_volumes = [volume for volume in session.volumes if volume.identifier in set(volume_ids)]
        if not selected_volumes:
            raise ValueError("Brak wybranych wolumenów do analizy")

        analysis = AnalysisResult(source=session.source)

        for index, volume in enumerate(selected_volumes, start=1):
            self._progress(f"Analiza wolumenu {volume.identifier}", percentage=self._progress_percentage(index, len(selected_volumes)))

            filesystem = self._detect_filesystem(volume)
            finding = self._detect_encryption(volume)
            metadata: MetadataResult | None = None

            if collect_metadata:
                metadata = self._metadata_scanner.scan(volume)

            analysis.volumes.append(
                VolumeAnalysis(
                    volume=volume,
                    filesystem=filesystem,
                    encryption=finding,
                    metadata=metadata,
                )
            )

        self._progress("Analiza zakończona", percentage=95)
        return analysis

    # ------------------------------------------------------------------
    # Raportowanie
    # ------------------------------------------------------------------

    def export_report(self, result: AnalysisResult, destination: Path, fmt: ExportFormat) -> Path:
        """Eksportuje raport do wskazanego pliku."""

        path = self._report_exporter.export(result, destination, fmt)
        self._progress("Raport został zapisany", percentage=100)
        return path

    # ------------------------------------------------------------------
    # Operacje pomocnicze
    # ------------------------------------------------------------------

    def _detect_filesystem(self, volume: Volume) -> FileSystemType:
        try:
            fs_type = self._filesystem_detector.detect(volume)
            volume.filesystem = fs_type
            return fs_type
        except Exception as exc:  # pragma: no cover - logowanie błędów środowiskowych
            self._logger.warning("filesystem-detection-failed", volume=volume.identifier, error=str(exc))
            volume.filesystem = FileSystemType.UNKNOWN
            return FileSystemType.UNKNOWN

    def _detect_encryption(self, volume: Volume) -> EncryptionFinding:
        fallback: EncryptionFinding | None = None
        for detector in self._encryption_detectors:
            try:
                finding = detector.analyze_volume(volume)
            except Exception as exc:  # pragma: no cover - logowanie błędów środowiskowych
                self._logger.warning(
                    "encryption-detection-failed",
                    volume=volume.identifier,
                    detector=getattr(detector, "name", detector.__class__.__name__),
                    error=str(exc),
                )
                continue

            if finding.status != EncryptionStatus.UNKNOWN:
                volume.encryption = finding.status
                return finding
            fallback = fallback or finding

        result = fallback or EncryptionFinding(status=EncryptionStatus.UNKNOWN)
        volume.encryption = result.status
        return result

    def _progress(self, message: str, *, percentage: int | None = None) -> None:
        self._progress_reporter.update(message, percentage=percentage)

    @staticmethod
    def _progress_percentage(current: int, total: int) -> int:
        if total == 0:
            return 50
        return int((current / total) * 80) + 15