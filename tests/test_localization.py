"""Testy lokalizacji interfejsu użytkownika."""

from __future__ import annotations

import pytest

from crypto_analyzer.ui.localization import LocalizationManager


def test_localization_switches_language() -> None:
    manager = LocalizationManager()
    assert manager.text("app.title") == "CryptoAnalyzer"

    manager.set_locale("en")
    assert manager.text("button.image") == "Disk Image"


def test_localization_rejects_unknown_locale() -> None:
    manager = LocalizationManager()
    with pytest.raises(ValueError):
        manager.set_locale("de")


def test_missing_key_raises_error() -> None:
    manager = LocalizationManager()
    with pytest.raises(KeyError):
        manager.text("nonexistent.key")
