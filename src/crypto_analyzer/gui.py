"""Punkt wejściowy dla aplikacji GUI."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from crypto_analyzer.shared import configure_logging
from crypto_analyzer.shared.error_reporting import install_crash_reporting
from crypto_analyzer.ui.main_window import MainWindow


def main() -> int:
    """Uruchamia aplikację GUI."""
    install_crash_reporting()
    configure_logging()
    app = QApplication(sys.argv)
    app.setApplicationName("CryptoAnalyzer")
    app.setOrganizationName("CryptoAnalyzer Team")

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
