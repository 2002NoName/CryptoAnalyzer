"""Testy głównego okna GUI."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication

from crypto_analyzer.ui import MainWindow


@pytest.fixture(scope="module")
def qapp():
    """Tworzy globalną instancję QApplication dla testów."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


def test_main_window_creation(qapp) -> None:
    """Test tworzenia głównego okna."""
    window = MainWindow()
    assert window.windowTitle() == "CryptoAnalyzer"
    assert window.minimumWidth() == 800
    assert window.minimumHeight() == 600


def test_main_window_shows(qapp, qtbot) -> None:
    """Test wyświetlania okna."""
    window = MainWindow()
    qtbot.addWidget(window)
    window.show()
    assert window.isVisible()
