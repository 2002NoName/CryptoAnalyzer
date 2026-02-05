"""AI analysis dialog (optional feature)."""

from __future__ import annotations

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

from crypto_analyzer.core.models import AnalysisResult

from .localization import LocalizationManager


class _AiSignals(QObject):
    finished = Signal(object)
    failed = Signal(object)


class _AiWorker(QRunnable):
    def __init__(self, fn):
        super().__init__()
        self._fn = fn
        self.signals = _AiSignals()

    def run(self) -> None:  # pragma: no cover
        try:
            self.signals.finished.emit(self._fn())
        except Exception as exc:
            self.signals.failed.emit(exc)


class AiAnalysisDialog(QDialog):
    def __init__(
        self,
        *,
        service,
        result: AnalysisResult,
        localization: LocalizationManager,
        ui_locale: str,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._result = result
        self._localization = localization
        self._ui_locale = ui_locale
        self._thread_pool = QThreadPool.globalInstance()

        self.setWindowTitle(self._localization.text("ai.dialog.title"))
        self.setMinimumSize(720, 520)
        self.setModal(False)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        title = QLabel(self._localization.text("ai.section.title"))
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        self._summary_label = QLabel(self._localization.text("ai.summary.title"))
        layout.addWidget(self._summary_label)
        self._summary = QPlainTextEdit()
        self._summary.setReadOnly(True)
        self._summary.setMinimumHeight(110)
        layout.addWidget(self._summary)

        self._suspicious_label = QLabel(self._localization.text("ai.suspicious.title"))
        layout.addWidget(self._suspicious_label)
        self._suspicious = QPlainTextEdit()
        self._suspicious.setReadOnly(True)
        self._suspicious.setMinimumHeight(120)
        layout.addWidget(self._suspicious)

        self._next_steps_label = QLabel(self._localization.text("ai.next_steps.title"))
        layout.addWidget(self._next_steps_label)
        self._next_steps = QPlainTextEdit()
        self._next_steps.setReadOnly(True)
        self._next_steps.setMinimumHeight(90)
        layout.addWidget(self._next_steps)

        self._qa_label = QLabel(self._localization.text("ai.qa.title"))
        layout.addWidget(self._qa_label)

        qa_layout = QHBoxLayout()
        self._question = QLineEdit()
        self._question.setPlaceholderText(self._localization.text("ai.qa.placeholder"))
        qa_layout.addWidget(self._question, stretch=1)
        self._ask_button = QPushButton(self._localization.text("ai.qa.ask"))
        self._ask_button.clicked.connect(self._on_ask)
        qa_layout.addWidget(self._ask_button)
        layout.addLayout(qa_layout)

        self._answer = QPlainTextEdit()
        self._answer.setReadOnly(True)
        self._answer.setMinimumHeight(90)
        layout.addWidget(self._answer)

        self._start_insights()

    def _start_insights(self) -> None:
        running = self._localization.text("ai.status.running")
        self._summary.setPlainText(running)
        self._suspicious.setPlainText(running)
        self._next_steps.setPlainText(running)
        self._answer.setPlainText("")

        worker = _AiWorker(
            lambda: self._service.generate_summary_and_suspicious(
                self._result,
                ui_locale=self._ui_locale,
            )
        )
        worker.signals.finished.connect(self._on_insights_ready)
        worker.signals.failed.connect(self._on_insights_failed)
        self._thread_pool.start(worker)

    def _on_insights_ready(self, payload: object) -> None:
        if not isinstance(payload, dict):
            self._on_insights_failed(RuntimeError(self._localization.text("ai.error.invalid_output")))
            return
        self._summary.setPlainText(str(payload.get("summary", "")))
        self._suspicious.setPlainText(str(payload.get("suspicious", "")))
        self._next_steps.setPlainText(str(payload.get("next_steps", "")))

    def _on_insights_failed(self, error: object) -> None:
        self._summary.setPlainText("")
        self._suspicious.setPlainText("")
        self._next_steps.setPlainText("")
        self._answer.setPlainText(str(error))

    def _on_ask(self) -> None:
        question = (self._question.text() or "").strip()
        if not question:
            return

        self._ask_button.setEnabled(False)
        self._answer.setPlainText(self._localization.text("ai.status.running"))

        worker = _AiWorker(lambda: self._service.answer_question(self._result, question, ui_locale=self._ui_locale))
        worker.signals.finished.connect(self._on_answer_ready)
        worker.signals.failed.connect(self._on_answer_failed)
        self._thread_pool.start(worker)

    def _on_answer_ready(self, answer: object) -> None:
        self._answer.setPlainText(str(answer))
        self._ask_button.setEnabled(True)

    def _on_answer_failed(self, error: object) -> None:
        self._answer.setPlainText(str(error))
        self._ask_button.setEnabled(True)
