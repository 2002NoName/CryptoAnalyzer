"""Główne okno aplikacji GUI."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import List

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressDialog,
    QPushButton,
    QSpinBox,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from crypto_analyzer.core.analysis_manager import UnknownFilesystemError
from crypto_analyzer.core.models import (
    AnalysisResult,
    DiskSource,
    DirectoryNode,
    EncryptionStatus,
    FileMetadata,
    FileSystemType,
    Volume,
)
from crypto_analyzer.reporting import DefaultReportExporter, ExportFormat
from crypto_analyzer.shared.error_reporting import write_error_report
from .elevation import is_running_as_admin, request_elevation
from .localization import LocalizationManager
from .services import AnalysisConfig, AnalysisService
from .view_models import AnalysisState, AnalysisViewModel

try:  # optional
    from crypto_analyzer.ai import AiInsightsService, load_ai_config
except Exception:  # pragma: no cover - optional feature
    AiInsightsService = None  # type: ignore[assignment]
    load_ai_config = None  # type: ignore[assignment]

from .ai_dialog import AiAnalysisDialog


def _format_size(size: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024


class VolumeSelectionDialog(QDialog):
    """Dialog wyboru wolumenów przeznaczonych do analizy."""

    def __init__(
        self,
        volumes: List[Volume],
        localization: LocalizationManager,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._localization = localization
        self.setWindowTitle(self._localization.text("dialog.select.volumes.title"))
        self.resize(400, 300)

        layout = QVBoxLayout(self)

        description = QLabel(self._localization.text("dialog.select.volumes.description"))
        layout.addWidget(description)

        self._list = QListWidget()
        self._list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        for volume in volumes:
            filesystem_label = self._format_filesystem(volume)
            label = f"{volume.identifier} – {_format_size(volume.size)} – {filesystem_label}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, volume.identifier)
            self._list.addItem(item)
        self._list.selectAll()
        layout.addWidget(self._list)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def selected_volume_ids(self) -> List[str]:
        return [item.data(Qt.ItemDataRole.UserRole) for item in self._list.selectedItems()]

    def _format_filesystem(self, volume: Volume) -> str:
        fs = volume.filesystem
        if fs is FileSystemType.UNKNOWN:
            if volume.encryption is EncryptionStatus.ENCRYPTED:
                return self._localization.text("filesystem.encrypted")
            if volume.encryption is EncryptionStatus.PARTIALLY_ENCRYPTED:
                return self._localization.text("filesystem.partially_encrypted")
            return self._localization.text("filesystem.unknown")
        mapping = {
            FileSystemType.NTFS: "NTFS",
            FileSystemType.EXT2: "ext2",
            FileSystemType.EXT3: "ext3",
            FileSystemType.EXT4: "ext4",
            FileSystemType.FAT12: "FAT12",
            FileSystemType.FAT16: "FAT16",
            FileSystemType.FAT32: "FAT32",
            FileSystemType.EXFAT: "exFAT",
            FileSystemType.APFS: "APFS",
            FileSystemType.HFS_PLUS: "HFS+",
            FileSystemType.ISO9660: "ISO9660",
            FileSystemType.UFS: "UFS",
        }
        return mapping.get(fs, fs.value.upper())


class MainWindow(QMainWindow):
    """Główne okno aplikacji CryptoAnalyzer."""

    def __init__(
        self,
        *,
        service: AnalysisService | None = None,
        localization: LocalizationManager | None = None,
        view_model: AnalysisViewModel | None = None,
    ) -> None:
        super().__init__()

        self._service = service or AnalysisService()
        self._localization = localization or LocalizationManager()
        self._view_model = view_model or AnalysisViewModel(service=self._service)
        self._state: AnalysisState = self._view_model.state()
        self._last_result: AnalysisResult | None = None
        self._current_source: DiskSource | None = None
        self._current_description: str | None = None
        self._progress_dialog: QProgressDialog | None = None
        self._current_config: AnalysisConfig | None = None
        self._cancel_requested = False
        self._ai_enabled = False
        self._ai_service = None
        self._ai_dialog: AiAnalysisDialog | None = None

        self.setWindowTitle(self._text("app.title"))
        self.setMinimumSize(800, 600)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._title_label = QLabel()
        self._title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin: 20px;")
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._title_label)

        self._description_label = QLabel()
        self._description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._description_label.setStyleSheet("margin-bottom: 20px;")
        layout.addWidget(self._description_label)

        language_layout = QHBoxLayout()
        language_layout.setAlignment(Qt.AlignmentFlag.AlignRight)
        self._language_label = QLabel()
        language_layout.addWidget(self._language_label)

        self._language_selector = QComboBox()
        for locale, display in self._localization.available_locales().items():
            self._language_selector.addItem(display, locale)
        self._language_selector.currentIndexChanged.connect(self._on_language_changed)
        language_layout.addWidget(self._language_selector)
        layout.addLayout(language_layout)

        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(20)

        self._btn_physical = QPushButton()
        self._btn_physical.setMinimumSize(150, 60)
        self._btn_physical.clicked.connect(self._select_physical_disk)
        buttons_layout.addWidget(self._btn_physical)

        self._btn_image = QPushButton()
        self._btn_image.setMinimumSize(150, 60)
        self._btn_image.clicked.connect(self._select_disk_image)
        buttons_layout.addWidget(self._btn_image)

        layout.addLayout(buttons_layout)

        options_layout = QHBoxLayout()
        options_layout.setSpacing(10)
        options_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._metadata_checkbox = QCheckBox()
        self._metadata_checkbox.setChecked(False)
        self._metadata_checkbox.toggled.connect(self._on_metadata_toggled)
        options_layout.addWidget(self._metadata_checkbox)

        self._depth_label = QLabel()
        options_layout.addWidget(self._depth_label)

        self._depth_spin = QSpinBox()
        self._depth_spin.setRange(0, 25)
        self._depth_spin.setValue(3)
        self._depth_spin.setEnabled(False)
        options_layout.addWidget(self._depth_spin)

        self._workers_label = QLabel()
        options_layout.addWidget(self._workers_label)

        max_workers = max(1, min((os.cpu_count() or 1) * 2, 32))
        self._workers_spin = QSpinBox()
        self._workers_spin.setRange(1, max_workers)
        self._workers_spin.setValue(self._default_worker_count())
        self._workers_spin.setEnabled(False)
        options_layout.addWidget(self._workers_spin)

        options_layout.addStretch(1)
        layout.addLayout(options_layout)

        export_layout = QHBoxLayout()
        export_layout.setSpacing(10)
        export_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._btn_export_json = QPushButton()
        self._btn_export_json.clicked.connect(lambda: self._export_report(ExportFormat.JSON))
        export_layout.addWidget(self._btn_export_json)

        self._btn_export_csv = QPushButton()
        self._btn_export_csv.clicked.connect(lambda: self._export_report(ExportFormat.CSV))
        export_layout.addWidget(self._btn_export_csv)

        layout.addLayout(export_layout)

        self._results_tree = QTreeWidget()
        self._results_tree.setAlternatingRowColors(True)
        self._results_tree.setColumnWidth(0, 180)
        self._results_tree.setColumnWidth(1, 120)
        layout.addWidget(self._results_tree, stretch=1)

        # -----------------------------
        # AI (optional)
        # -----------------------------
        self._ai_title = QLabel()
        self._ai_title.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(self._ai_title)

        self._ai_disabled_label = QLabel()
        self._ai_disabled_label.setWordWrap(True)
        layout.addWidget(self._ai_disabled_label)

        self._ai_open_button = QPushButton()
        self._ai_open_button.clicked.connect(self._open_ai_dialog)
        layout.addWidget(self._ai_open_button)

        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("margin-top: 10px; color: #666;")
        layout.addWidget(self.status_label)

        self._set_export_buttons_enabled(False)

        self._connect_view_model()
        self._retranslate_ui()
        self._configure_ai_from_env()
        self.status_label.setText(self._text("label.status.ready"))

    # ------------------------------------------------------------------
    # Reakcje UI
    # ------------------------------------------------------------------

    def _default_worker_count(self) -> int:
        cores = os.cpu_count() or 1
        return min(max(1, cores), 16)

    def _on_metadata_toggled(self, enabled: bool) -> None:
        self._depth_spin.setEnabled(enabled)
        self._workers_spin.setEnabled(enabled)

    def _format_source_option(self, source: DiskSource) -> str:
        label = source.display_name
        details: list[str] = []
        if source.size_bytes:
            details.append(_format_size(source.size_bytes))
        if source.path:
            details.append(str(source.path))
        if details:
            label = f"{label} ({', '.join(details)})"
        return label

    def _select_physical_disk(self) -> None:
        try:
            sources = self._service.list_physical_sources()
        except Exception as exc:  # pragma: no cover - zależne od środowiska
            message = str(exc)
            QMessageBox.critical(
                self,
                self._text("dialog.select.physical.title"),
                message,
            )
            if self._is_permission_error(message):
                self.status_label.setText(self._text("dialog.select.physical.no_access"))
                self._show_elevation_dialog()
            else:
                self.status_label.setText(self._text("status.driver.unavailable"))
                return

        if not sources:
            QMessageBox.information(
                self,
                self._text("dialog.select.physical.title"),
                self._text("dialog.select.physical.none"),
            )
            self.status_label.setText(self._text("dialog.select.physical.none"))
            return

        options = [self._format_source_option(source) for source in sources]

        if all("access denied" in option.lower() for option in options):
            self.status_label.setText(self._text("dialog.select.physical.no_access"))
            self._show_elevation_dialog()
            return

        choice, accepted = QInputDialog.getItem(
            self,
            self._text("dialog.select.physical.title"),
            self._text("dialog.select.physical.prompt"),
            options,
            0,
            False,
        )

        if not accepted:
            self.status_label.setText(self._text("dialog.analyze.cancelled"))
            return

        selected_index = options.index(choice)
        selected = sources[selected_index]
        self._current_source = selected
        description = selected.display_name
        self._prepare_and_start_analysis(selected, description)

    def _select_disk_image(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            self._text("dialog.select.image.title"),
            "",
            f"{self._text('dialog.select.image.filter')};;{self._text('dialog.select.image.filter.all')}",
        )
        if not file_path:
            return

        image_path = Path(file_path)
        source = self._service.create_image_source(image_path)
        self._current_source = source
        self._prepare_and_start_analysis(source, image_path.name)

    def _prepare_and_start_analysis(self, source: DiskSource, description: str) -> None:
        self._current_source = source
        self._current_description = description
        self.status_label.setText(self._text("progress.preparing"))

        try:
            volumes = self._service.list_volumes(source)
        except Exception as exc:
            self._handle_analysis_error(exc)
            return

        if not volumes:
            QMessageBox.information(
                self,
                self._text("dialog.analyze.title"),
                self._text("dialog.analyze.no_volumes"),
            )
            self.status_label.setText(self._text("dialog.analyze.no_volumes"))
            return

        dialog = VolumeSelectionDialog(volumes, self._localization, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            self.status_label.setText(self._text("dialog.analyze.cancelled"))
            return

        selected_ids = dialog.selected_volume_ids()
        if not selected_ids:
            self.status_label.setText(self._text("dialog.analyze.no_selection"))
            return

        collect_metadata = bool(self._metadata_checkbox.isChecked())
        metadata_depth: int | None = None
        metadata_workers = 1
        if collect_metadata:
            depth_value = int(self._depth_spin.value())
            metadata_depth = None if depth_value == 0 else depth_value
            metadata_workers = int(self._workers_spin.value())

        config = AnalysisConfig(
            source=source,
            selected_volume_ids=tuple(selected_ids),
            collect_metadata=collect_metadata,
            metadata_depth=metadata_depth,
            metadata_workers=metadata_workers,
        )
        self._current_config = config

        self.status_label.setText(self._text("progress.running"))
        self._view_model.start_analysis(config)

    def _connect_view_model(self) -> None:
        self._view_model.analysisStarted.connect(self._on_analysis_started)
        self._view_model.progressChanged.connect(self._on_analysis_progress)
        self._view_model.analysisSucceeded.connect(self._on_analysis_succeeded)
        self._view_model.analysisFailed.connect(self._on_analysis_failed)
        self._view_model.analysisCancelled.connect(self._on_analysis_cancelled)
        self._view_model.analysisFinished.connect(self._on_analysis_finished)

    def _on_analysis_started(self) -> None:
        self._set_ui_enabled(False)
        self._last_result = None
        if self._progress_dialog is None:
            self._progress_dialog = QProgressDialog(
                self._text("progress.running"),
                self._text("dialog.progress.cancel"),
                0,
                100,
                self,
            )
            self._progress_dialog.setWindowTitle(self._text("dialog.analyze.title"))
            self._progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
            self._progress_dialog.setAutoClose(False)
            self._progress_dialog.setAutoReset(False)
            self._progress_dialog.canceled.connect(self._cancel_analysis)
            self._progress_dialog.show()

    def _on_analysis_progress(self, message: str, percentage: int) -> None:
        message = self._translate_progress_message(message)
        self.status_label.setText(message)
        if self._progress_dialog is None:
            return
        try:
            self._progress_dialog.setLabelText(message)
            if percentage >= 0:
                self._progress_dialog.setValue(percentage)
        except Exception:
            # best-effort updates; progress dialog might be closing
            pass

    def _on_analysis_succeeded(self, result: AnalysisResult) -> None:
        self._last_result = result
        self._set_export_buttons_enabled(True)
        self._populate_results_tree(result)
        self._update_ai_button_state()
        description = self._current_description
        if description:
            self.status_label.setText(
                self._text("status.analysis.completed").format(description=description)
            )
        else:
            self.status_label.setText(self._text("status.analysis.completed.generic"))

    def _on_analysis_failed(self, error: object) -> None:
        if isinstance(error, UnknownFilesystemError):
            self._handle_unknown_filesystem(error)
            return
        if isinstance(error, Exception):
            self._handle_analysis_error(error)
            return
        self._handle_analysis_error(RuntimeError(str(error)))

    def _on_analysis_cancelled(self) -> None:
        if not self._cancel_requested:
            QMessageBox.information(
                self,
                self._text("dialog.analyze.title"),
                self._text("dialog.analyze.cancelled"),
            )
        self.status_label.setText(self._text("status.analysis.cancelled"))
        self._current_config = None

    def _on_analysis_finished(self) -> None:
        self._set_ui_enabled(True)
        self._dismiss_progress_dialog()
        self._cancel_requested = False
        self._current_config = None

    def _dismiss_progress_dialog(self) -> None:
        if self._progress_dialog is None:
            return
        try:
            self._progress_dialog.canceled.disconnect(self._cancel_analysis)
        except Exception:
            pass
        try:
            self._progress_dialog.close()
        finally:
            self._progress_dialog = None

    def _cancel_analysis(self) -> None:
        if self._cancel_requested:
            return
        self._cancel_requested = True
        self.status_label.setText(self._text("progress.cancelling"))
        if self._progress_dialog is not None:
            self._progress_dialog.setLabelText(self._text("progress.cancelling"))
            self._progress_dialog.setCancelButtonText("")
            self._progress_dialog.setCancelButton(None)
        self._view_model.cancel_analysis()

    # ------------------------------------------------------------------
    # Lokalizacja i stan UI
    # ------------------------------------------------------------------

    def _on_language_changed(self, index: int) -> None:
        locale = self._language_selector.itemData(index)
        if not locale:
            return
        if locale == self._localization.locale:
            return
        self._localization.set_locale(locale)
        self._retranslate_ui()
        self._configure_ai_from_env()

    # ------------------------------------------------------------------
    # AI integration (optional)
    # ------------------------------------------------------------------

    def _configure_ai_from_env(self) -> None:
        self._ai_title.setText(self._text("ai.section.title"))
        self._ai_open_button.setText(self._text("ai.button.open"))

        self._ai_enabled = False
        self._ai_service = None
        if load_ai_config is not None and AiInsightsService is not None:
            cfg = load_ai_config()
            if cfg is not None:
                self._ai_enabled = True
                self._ai_service = AiInsightsService(cfg)

        # Show/hide button depending on enablement.
        self._ai_disabled_label.setVisible(not self._ai_enabled)
        self._ai_disabled_label.setText(self._text("ai.section.disabled") if not self._ai_enabled else "")

        self._ai_open_button.setVisible(self._ai_enabled)
        self._update_ai_button_state()

    def _update_ai_button_state(self) -> None:
        enabled = bool(self._ai_enabled and self._ai_service is not None and self._last_result is not None)
        self._ai_open_button.setEnabled(enabled)

    def _open_ai_dialog(self) -> None:
        if not self._ai_enabled or self._ai_service is None or self._last_result is None:
            return

        # Keep reference so the dialog isn't garbage-collected.
        self._ai_dialog = AiAnalysisDialog(
            service=self._ai_service,
            result=self._last_result,
            localization=self._localization,
            ui_locale=self._localization.locale,
            parent=self,
        )
        self._ai_dialog.show()

    def _retranslate_ui(self) -> None:
        self.setWindowTitle(self._text("app.title"))
        self._title_label.setText(self._text("app.title"))
        self._description_label.setText(self._text("app.description"))
        self._language_label.setText(self._text("language.label"))
        # ensure selector shows correct labels
        for index in range(self._language_selector.count()):
            locale = self._language_selector.itemData(index)
            if locale in self._localization.available_locales():
                self._language_selector.setItemText(
                    index,
                    self._localization.available_locales()[locale],
                )
        current_index = self._language_selector.findData(self._localization.locale)
        if current_index >= 0:
            self._language_selector.blockSignals(True)
            self._language_selector.setCurrentIndex(current_index)
            self._language_selector.blockSignals(False)
        self._btn_physical.setText(self._text("button.physical"))
        self._btn_image.setText(self._text("button.image"))
        self._metadata_checkbox.setText(self._text("checkbox.metadata"))
        self._depth_label.setText(self._text("label.depth"))
        self._depth_spin.setSpecialValueText(self._text("label.depth.unlimited"))
        self._workers_label.setText(self._text("label.workers"))
        self._btn_export_json.setText(self._text("button.export.json"))
        self._btn_export_csv.setText(self._text("button.export.csv"))
        self._results_tree.setHeaderLabels(
            [
                self._text("column.name"),
                self._text("column.type"),
                self._text("column.size"),
                self._text("column.encryption"),
                self._text("column.details"),
            ]
        )
        if self._last_result is not None:
            self._populate_results_tree(self._last_result)

    def _set_ui_enabled(self, enabled: bool) -> None:
        self._btn_physical.setEnabled(enabled)
        self._btn_image.setEnabled(enabled)
        self._metadata_checkbox.setEnabled(enabled)
        self._depth_spin.setEnabled(enabled and self._metadata_checkbox.isChecked())
        self._workers_spin.setEnabled(enabled and self._metadata_checkbox.isChecked())
        self._btn_export_csv.setEnabled(enabled and self._last_result is not None)
        self._btn_export_json.setEnabled(enabled and self._last_result is not None)
        self._language_selector.setEnabled(enabled)

    def _text(self, key: str) -> str:
        return self._localization.text(key)

    def _show_elevation_dialog(self) -> None:
        if is_running_as_admin():
            return

        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.setWindowTitle(self._text("dialog.select.physical.title"))
        dialog.setText(self._text("dialog.elevation.required"))
        elevate_button = dialog.addButton(self._text("dialog.elevation.button"), QMessageBox.ButtonRole.ActionRole)
        dialog.addButton(QMessageBox.StandardButton.Cancel)
        dialog.exec()

        if dialog.clickedButton() is elevate_button:
            if request_elevation():
                QApplication.instance().quit()
            else:
                QMessageBox.critical(
                    self,
                    self._text("dialog.select.physical.title"),
                    self._text("dialog.elevation.failed"),
                )

    def _handle_analysis_error(self, error: Exception) -> None:
        message = str(error)

        # Pre-analysis errors can happen before the progress dialog exists, but if it does,
        # close it so dialogs remain visible.
        self._dismiss_progress_dialog()

        report_path: str | None = None
        report_error: str | None = None
        try:
            report = write_error_report(
                error,
                where="gui.handle_analysis_error",
                context={
                    "current_description": self._current_description,
                    "metadata_enabled": bool(self._metadata_checkbox.isChecked()),
                    "scan_depth": int(self._depth_spin.value()),
                    "workers": int(self._workers_spin.value()),
                },
            )
            report_path = str(report.path.resolve())
        except Exception as report_exc:  # pragma: no cover - best effort
            report_error = str(report_exc)

        if report_path is not None:
            report_line = self._text("dialog.analyze.error_report_saved").format(path=report_path)
        else:
            report_line = self._text("dialog.analyze.error_report_failed")
            if report_error:
                report_line = f"{report_line}\n{report_error}"
        QMessageBox.critical(
            self,
            self._text("dialog.analyze.title"),
            f"{self._text('dialog.analyze.error')}\n{message}\n\n{report_line}",
        )

        if self._is_permission_error(message):
            self.status_label.setText(self._text("dialog.select.physical.no_access"))
            self._show_elevation_dialog()
        else:
            self.status_label.setText(self._text("status.analysis.failed"))

    def _handle_unknown_filesystem(self, error: UnknownFilesystemError) -> None:
        volume_id = error.volume.identifier
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.setWindowTitle(self._text("dialog.unknown_fs.title"))
        dialog.setText(
            self._text("dialog.unknown_fs.message").format(identifier=volume_id)
        )
        skip_button = dialog.addButton(self._text("dialog.unknown_fs.skip"), QMessageBox.ButtonRole.AcceptRole)
        dialog.addButton(self._text("dialog.unknown_fs.abort"), QMessageBox.ButtonRole.RejectRole)
        dialog.exec()

        if dialog.clickedButton() is not skip_button or self._current_config is None:
            self.status_label.setText(self._text("status.analysis.failed"))
            return

        remaining = tuple(
            vid for vid in self._current_config.selected_volume_ids if vid != volume_id
        )
        if not remaining:
            QMessageBox.information(
                self,
                self._text("dialog.unknown_fs.title"),
                self._text("dialog.unknown_fs.no_remaining"),
            )
            self.status_label.setText(self._text("dialog.analyze.no_volumes"))
            self._current_config = None
            return

        new_config = replace(self._current_config, selected_volume_ids=remaining)
        self._current_config = new_config
        self.status_label.setText(self._text("dialog.unknown_fs.skipping").format(identifier=volume_id))

        QTimer.singleShot(0, lambda: self._view_model.start_analysis(new_config))

    @staticmethod
    def _is_permission_error(message: str) -> bool:
        lowered = message.lower()
        return any(
            phrase in lowered
            for phrase in (
                "access is denied",
                "permission denied",
                "access denied",
            )
        )

    def _set_export_buttons_enabled(self, enabled: bool) -> None:
        self._btn_export_json.setEnabled(enabled)
        self._btn_export_csv.setEnabled(enabled)

    def _export_report(self, fmt: ExportFormat) -> None:
        if self._last_result is None:
            QMessageBox.information(
                self,
                self._text("dialog.analyze.title"),
                self._text("dialog.report.no_results"),
            )
            return

        if fmt is ExportFormat.JSON:
            filter_text = self._text("dialog.report.filter.json")
            suffix = ".json"
        else:
            filter_text = self._text("dialog.report.filter.csv")
            suffix = ".csv"

        default_name = f"report{suffix}"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            self._text("dialog.report.title"),
            str(Path.home() / default_name),
            f"{filter_text};;All files (*)",
        )

        if not file_path:
            return

        destination = Path(file_path)
        exporter = DefaultReportExporter()

        try:
            exporter.export(self._last_result, destination, fmt)
        except Exception as exc:  # pragma: no cover - błędy środowiskowe
            QMessageBox.critical(
                self,
                self._text("dialog.report.title"),
                f"{self._text('dialog.report.error')}\n{exc}",
            )
            self.status_label.setText(self._text("dialog.report.error"))
            return

        QMessageBox.information(
            self,
            self._text("dialog.report.title"),
            f"{self._text('dialog.report.saved')} {destination}",
        )
        self.status_label.setText(f"{self._text('dialog.report.saved')} {destination}")

    def _populate_results_tree(self, result: AnalysisResult) -> None:
        self._results_tree.clear()
        for analysis in result.volumes:
            finding = analysis.encryption
            encryption_status = self._format_encryption_status(finding.status)
            details = finding.algorithm or "-"
            if finding.version:
                details = f"{details} ({finding.version})" if details != "-" else finding.version

            volume_item = QTreeWidgetItem(
                [
                    analysis.volume.identifier,
                    self._text("tree.volume").format(filesystem=analysis.filesystem.value.upper()),
                    _format_size(analysis.volume.size),
                    encryption_status,
                    details,
                ]
            )
            self._results_tree.addTopLevelItem(volume_item)

            if analysis.metadata is None:
                note_item = QTreeWidgetItem([
                    self._text("tree.metadata_skipped"),
                    self._text("tree.info"),
                    "-",
                    "-",
                    "",
                ])
                note_item.setDisabled(True)
                volume_item.addChild(note_item)
                continue

            root_node = analysis.metadata.root
            root_item = QTreeWidgetItem([
                root_node.name,
                self._text("tree.directory"),
                "-",
                "-",
                self._format_entry_details(
                    str(root_node.path),
                    root_node.owner,
                    root_node.modified_at,
                    owner_label=self._text("details.owner"),
                    mtime_label=self._text("details.mtime"),
                ),
            ])
            volume_item.addChild(root_item)
            self._add_directory_children(root_item, root_node)
            volume_item.setExpanded(True)
            root_item.setExpanded(True)

        self._results_tree.resizeColumnToContents(0)

    def _add_directory_children(self, parent_item: QTreeWidgetItem, node: DirectoryNode) -> None:
        for subdir in node.subdirectories:
            dir_item = QTreeWidgetItem([
                subdir.name,
                self._text("tree.directory"),
                "-",
                "-",
                self._format_entry_details(
                    str(subdir.path),
                    subdir.owner,
                    subdir.modified_at,
                    owner_label=self._text("details.owner"),
                    mtime_label=self._text("details.mtime"),
                ),
            ])
            parent_item.addChild(dir_item)
            self._add_directory_children(dir_item, subdir)

        for file_metadata in node.files:
            file_item = QTreeWidgetItem([
                file_metadata.name,
                self._text("tree.file"),
                _format_size(file_metadata.size),
                self._format_encryption_status(file_metadata.encryption),
                self._format_entry_details(
                    str(file_metadata.path),
                    file_metadata.owner,
                    file_metadata.modified_at,
                    owner_label=self._text("details.owner"),
                    mtime_label=self._text("details.mtime"),
                ),
            ])
            parent_item.addChild(file_item)

    @staticmethod
    def _format_entry_details(
        path: str,
        owner: str | None,
        modified_at: str | None,
        *,
        owner_label: str = "owner",
        mtime_label: str = "mtime",
    ) -> str:
        owner_value = owner if owner else "-"
        parts = [path, f"{owner_label}: {owner_value}"]
        if modified_at:
            parts.append(f"{mtime_label}: {modified_at}")
        return " | ".join(parts)

    @staticmethod
    def _pretty_status(value: str) -> str:
        parts = value.replace("_", " ").split()
        return " ".join(part.capitalize() for part in parts) if parts else value

    def _format_encryption_status(self, status: EncryptionStatus) -> str:
        key = f"encryption.status.{status.value}"
        try:
            return self._text(key)
        except KeyError:
            return self._pretty_status(status.value)

    def _format_result_summary(self, result: AnalysisResult, *, collect_metadata: bool) -> str:
        lines = [
            self._text("summary.source").format(display_name=result.source.display_name)
        ]
        for volume_result in result.volumes:
            finding = volume_result.encryption
            algo = finding.algorithm or "-"
            encrypt_status = self._format_encryption_status(finding.status)
            lines.append(
                self._text("summary.volume").format(
                    identifier=volume_result.volume.identifier,
                    filesystem=volume_result.filesystem.value.upper(),
                    encryption=encrypt_status,
                    algorithm=algo,
                )
            )

            if not collect_metadata:
                continue

            if volume_result.metadata is not None:
                lines.append(self._text("summary.metadata.volume.collected"))
                continue

            lines.append(self._text("summary.metadata.volume.skipped"))

        lines.append(self._text("summary.totals.volumes").format(count=len(result.volumes)))
        lines.append(self._text("summary.totals.files").format(count=result.total_files()))
        lines.append(self._text("summary.totals.directories").format(count=result.total_directories()))
        lines.append(
            self._text("summary.metadata.enabled" if collect_metadata else "summary.metadata.disabled")
        )
        return "\n".join(lines)

    def _translate_progress_message(self, message: str) -> str:
        if self._localization.locale == "pl":
            return message

        lines = message.splitlines()
        main = lines[0] if lines else message
        detail = "\n".join(lines[1:]) if len(lines) > 1 else None

        if detail:
            detail = self._translate_metadata_detail(detail)

        translated = self._translate_progress_main(main)
        if detail:
            return f"{translated}\n{detail}"
        return translated

    def _translate_progress_main(self, text: str) -> str:
        import re

        if text == "Inicjalizacja sesji":
            return self._text("progress.session.init")

        match = re.match(r"^Wykryto (\d+) wolumen\(y\)$", text)
        if match:
            return self._text("progress.session.detected_volumes").format(count=int(match.group(1)))

        match = re.match(r"^Wolumen (.+): przygotowanie$", text)
        if match:
            return self._text("progress.volume.preparing").format(identifier=match.group(1))

        match = re.match(r"^Wolumen (.+): analiza szyfrowania$", text)
        if match:
            return self._text("progress.volume.encryption").format(identifier=match.group(1))

        match = re.match(r"^Wolumen (.+): skanowanie metadanych \((\d+)%\)$", text)
        if match:
            return self._text("progress.volume.metadata_with_percent").format(
                identifier=match.group(1),
                percent=int(match.group(2)),
            )

        match = re.match(r"^Wolumen (.+): skanowanie metadanych$", text)
        if match:
            return self._text("progress.volume.metadata").format(identifier=match.group(1))

        match = re.match(r"^Wolumen (.+): analiza zakończona$", text)
        if match:
            return self._text("progress.volume.completed").format(identifier=match.group(1))

        match = re.match(r"^Wolumen (.+): metadane pominięte \((.+)\)$", text)
        if match:
            reason = self._translate_metadata_reason(match.group(2))
            return self._text("progress.volume.metadata_skipped").format(
                identifier=match.group(1),
                reason=reason,
            )

        if text == "Analiza zakończona":
            return self._text("progress.analysis.completed")

        if text == "Raport został zapisany":
            return self._text("progress.report.saved")

        return text

    def _translate_metadata_detail(self, detail: str) -> str:
        if detail.startswith("Katalog: "):
            path = detail.removeprefix("Katalog: ")
            return self._text("progress.metadata.detail.directory").format(path=path)
        if detail.startswith("Plik: "):
            path = detail.removeprefix("Plik: ")
            return self._text("progress.metadata.detail.file").format(path=path)
        return detail

    def _translate_metadata_reason(self, reason: str) -> str:
        if reason == "nieznany system plików":
            return self._text("progress.metadata.reason.unknown_fs")
        if reason.startswith("wykryto "):
            algorithm = reason.removeprefix("wykryto ")
            return self._text("progress.metadata.reason.detected").format(algorithm=algorithm)
        return reason
