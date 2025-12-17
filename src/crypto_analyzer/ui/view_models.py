"""Modele widoków wykorzystywane przez GUI CryptoAnalyzer."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

from crypto_analyzer.core import AnalysisCancelledError
from crypto_analyzer.core.models import AnalysisResult
from .services import AnalysisConfig, AnalysisService


class _AnalysisWorkerSignals(QObject):
    """Zestaw sygnałów emitowanych przez pracownika analizy."""

    started = Signal()
    progress = Signal(str, int)
    finished = Signal(object)
    failed = Signal(object)
    cancelled = Signal()


class _AnalysisWorker(QRunnable):
    """Pracownik uruchamiający analizę w wątku roboczym."""

    def __init__(self, service: AnalysisService, config: AnalysisConfig) -> None:
        super().__init__()
        self._service = service
        self._config = config
        self._cancel_event = threading.Event()
        self.signals = _AnalysisWorkerSignals()

    def run(self) -> None:  # pragma: no cover - wykonywane w wątku roboczym
        self.signals.started.emit()
        try:
            result = self._service.run_analysis(
                self._config,
                progress=lambda message, percentage: self.signals.progress.emit(
                    message,
                    percentage if percentage is not None else -1,
                ),
                cancel_event=self._cancel_event,
            )
        except AnalysisCancelledError:
            self.signals.cancelled.emit()
            return
        except Exception as exc:  # pragma: no cover - sygnalizacja błędów
            self.signals.failed.emit(exc)
            return

        self.signals.finished.emit(result)

    def cancel(self) -> None:
        self._cancel_event.set()


@dataclass(slots=True)
class AnalysisState:
    running: bool = False
    last_result: Optional[AnalysisResult] = None


class AnalysisViewModel(QObject):
    """Warstwa MVVM pośrednicząca między GUI a serwisem analizy."""

    analysisStarted = Signal()
    progressChanged = Signal(str, int)
    analysisSucceeded = Signal(object)
    analysisFailed = Signal(object)
    analysisCancelled = Signal()
    analysisFinished = Signal()

    def __init__(self, service: AnalysisService | None = None, *, thread_pool: QThreadPool | None = None) -> None:
        super().__init__()
        self._service = service or AnalysisService()
        self._thread_pool = thread_pool or QThreadPool.globalInstance()
        self._state = AnalysisState()
        self._current_worker: _AnalysisWorker | None = None

    # ------------------------------------------------------------------
    # API publiczne
    # ------------------------------------------------------------------

    def start_analysis(self, config: AnalysisConfig) -> None:
        if self._state.running:
            return

        worker = _AnalysisWorker(self._service, config)
        worker.signals.started.connect(self._on_worker_started)
        worker.signals.progress.connect(self._on_worker_progress)
        worker.signals.failed.connect(self._on_worker_failed)
        worker.signals.finished.connect(self._on_worker_finished)
        worker.signals.cancelled.connect(self._on_worker_cancelled)

        self._state.running = True
        self._current_worker = worker
        self._thread_pool.start(worker)

    def state(self) -> AnalysisState:
        return self._state

    def cancel_analysis(self) -> None:
        if not self._state.running or self._current_worker is None:
            return
        self._current_worker.cancel()

    # ------------------------------------------------------------------
    # Sloty wewnętrzne
    # ------------------------------------------------------------------

    def _on_worker_started(self) -> None:
        self.analysisStarted.emit()

    def _on_worker_progress(self, message: str, percentage: int) -> None:
        self.progressChanged.emit(message, percentage)

    def _on_worker_failed(self, error: object) -> None:
        self._state.running = False
        self._current_worker = None
        self.analysisFailed.emit(error)
        self.analysisFinished.emit()

    def _on_worker_finished(self, result: AnalysisResult) -> None:
        self._state.running = False
        self._current_worker = None
        self._state.last_result = result
        self.analysisSucceeded.emit(result)
        self.analysisFinished.emit()

    def _on_worker_cancelled(self) -> None:
        self._state.running = False
        self._current_worker = None
        self.analysisCancelled.emit()
        self.analysisFinished.emit()
