"""Zarządzanie pełnym cyklem analizy źródła danych."""

from __future__ import annotations

import threading
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
from crypto_analyzer.metadata import MetadataResult, MetadataScanCancelled, MetadataScanner
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


class UnknownFilesystemError(RuntimeError):
    """Sygnał, że napotkano nieobsługiwany system plików."""

    def __init__(self, volume: Volume) -> None:
        self.volume = volume
        message = f"Wolumen {volume.identifier} posiada nieobsługiwany system plików."
        super().__init__(message)


class AnalysisCancelledError(RuntimeError):
    """Zgłaszane, gdy analiza zostanie anulowana przez użytkownika."""


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

    def analyze(
        self,
        volume_ids: Sequence[str],
        *,
        collect_metadata: bool = True,
        cancel_event: threading.Event | None = None,
    ) -> AnalysisResult:
        """Analizuje wybrane wolumeny i zwraca wyniki."""

        session = self.session()
        selected_volumes = [volume for volume in session.volumes if volume.identifier in set(volume_ids)]
        if not selected_volumes:
            raise ValueError("Brak wybranych wolumenów do analizy")

        analysis = AnalysisResult(source=session.source)

        for index, volume in enumerate(selected_volumes, start=1):
            self._check_cancel(cancel_event)
            start, end = self._progress_bounds(index, len(selected_volumes))
            self._progress(f"Wolumen {volume.identifier}: przygotowanie", percentage=start)

            filesystem = self._detect_filesystem(volume)

            self._progress(f"Wolumen {volume.identifier}: analiza szyfrowania", percentage=start)
            finding = self._detect_encryption(volume)
            metadata: MetadataResult | None = None
            skip_metadata = filesystem is FileSystemType.UNKNOWN or finding.status in {
                EncryptionStatus.ENCRYPTED,
                EncryptionStatus.PARTIALLY_ENCRYPTED,
            }

            if collect_metadata and not skip_metadata:
                self._check_cancel(cancel_event)
                self._progress(f"Wolumen {volume.identifier}: skanowanie metadanych", percentage=start)

                def _metadata_progress(percent: int, kind: str | None, path: str | None) -> None:
                    self._check_cancel(cancel_event)
                    interpolated = self._interpolate_progress(start, end, percent)
                    detail = self._format_metadata_detail(kind, path)
                    message = f"Wolumen {volume.identifier}: skanowanie metadanych ({percent}%)"
                    if detail:
                        message = f"{message}\n{detail}"
                    self._progress(message, percentage=interpolated)

                try:
                    metadata = self._metadata_scanner.scan(
                        volume,
                        progress=_metadata_progress,
                        cancel_event=cancel_event,
                    )
                except MetadataScanCancelled as exc:
                    raise AnalysisCancelledError("Analiza przerwana podczas skanowania metadanych") from exc
                except Exception as exc:  # pragma: no cover - zależne od środowiska / uszkodzone obrazy
                    self._logger.warning(
                        "metadata-scan-failed",
                        volume=volume.identifier,
                        filesystem=filesystem.value,
                        error=str(exc),
                    )
                    metadata = None
                self._check_cancel(cancel_event)
                self._progress(f"Wolumen {volume.identifier}: analiza zakończona", percentage=end)
            else:
                self._check_cancel(cancel_event)
                if skip_metadata:
                    if filesystem is FileSystemType.UNKNOWN and finding.status in {
                        EncryptionStatus.NOT_DETECTED,
                        EncryptionStatus.UNKNOWN,
                    }:
                        reason = "nieznany system plików"
                    else:
                        algorithm = finding.algorithm or "szyfrowanie"
                        reason = f"wykryto {algorithm}"
                    self._progress(f"Wolumen {volume.identifier}: metadane pominięte ({reason})", percentage=end)
                else:
                    self._progress(f"Wolumen {volume.identifier}: analiza zakończona", percentage=end)

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

    def export_report(self, result: AnalysisResult, destination: Path, fmt: ExportFormat) -> Path:
        """Eksportuje raport do wskazanego pliku."""

        path = self._report_exporter.export(result, destination, fmt)
        self._progress("Raport został zapisany", percentage=100)
        return path

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

            if finding.status in {EncryptionStatus.ENCRYPTED, EncryptionStatus.PARTIALLY_ENCRYPTED}:
                volume.encryption = finding.status
                return finding

            if finding.status is EncryptionStatus.UNKNOWN:
                fallback = fallback or finding
                continue
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

    @staticmethod
    def _interpolate_progress(start: int, end: int, percent: int) -> int:
        span = max(end - start, 1)
        clamped = max(0, min(percent, 100))
        return start + int((clamped / 100) * span)

    @staticmethod
    def _progress_bounds(index: int, total: int) -> tuple[int, int]:
        if index <= 1:
            start = 15
        else:
            start = AnalysisManager._progress_percentage(index - 1, total)
        end = AnalysisManager._progress_percentage(index, total)
        if end < start:
            end = start
        return start, end

    @staticmethod
    def _format_metadata_detail(kind: str | None, path: str | None) -> str | None:
        if path is None:
            return None
        if kind == "directory":
            return f"Katalog: {path}"
        if kind == "file":
            return f"Plik: {path}"
        return path

    @staticmethod
    def _check_cancel(cancel_event: threading.Event | None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise AnalysisCancelledError("Analiza została anulowana")