"""Główne okno aplikacji GUI."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class MainWindow(QMainWindow):
    """Główne okno aplikacji CryptoAnalyzer."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("CryptoAnalyzer")
        self.setMinimumSize(800, 600)

        # Główny widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout
        layout = QVBoxLayout(central_widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Nagłówek
        title = QLabel("CryptoAnalyzer")
        title.setStyleSheet("font-size: 24px; font-weight: bold; margin: 20px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Opis
        description = QLabel(
            "Narzędzie do analizy dysków i obrazów dysków\n"
            "pod kątem szyfrowania oraz struktury plików"
        )
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description.setStyleSheet("margin-bottom: 40px;")
        layout.addWidget(description)

        # Przyciski wyboru źródła
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(20)

        btn_physical = QPushButton("Dysk fizyczny")
        btn_physical.setMinimumSize(150, 60)
        btn_physical.clicked.connect(self._select_physical_disk)
        buttons_layout.addWidget(btn_physical)

        btn_image = QPushButton("Obraz dysku")
        btn_image.setMinimumSize(150, 60)
        btn_image.clicked.connect(self._select_disk_image)
        buttons_layout.addWidget(btn_image)

        layout.addLayout(buttons_layout)

        # Status
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("margin-top: 40px; color: #666;")
        layout.addWidget(self.status_label)

    def _select_physical_disk(self) -> None:
        """Obsługa wyboru dysku fizycznego."""
        self.status_label.setText("Funkcja wyboru dysku fizycznego w przygotowaniu...")

    def _select_disk_image(self) -> None:
        """Obsługa wyboru obrazu dysku."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Wybierz obraz dysku",
            "",
            "Obrazy dysków (*.img *.dd *.raw *.e01 *.vhd *.vhdx);;Wszystkie pliki (*)",
        )
        if file_path:
            self.status_label.setText(f"Wybrano: {file_path}")
            # TODO: Przejście do widoku analizy
