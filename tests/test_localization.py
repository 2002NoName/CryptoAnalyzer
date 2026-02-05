"""Testy lokalizacji interfejsu użytkownika."""

from __future__ import annotations

import pytest

from crypto_analyzer.ui import localization as ui_localization
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


def test_localization_tables_are_complete() -> None:
    translations = ui_localization._TRANSLATIONS
    base_keys = set(translations["pl"].keys())

    for locale, table in translations.items():
        keys = set(table.keys())
        missing = base_keys - keys
        extra = keys - base_keys
        assert not missing, f"Missing keys in {locale}: {sorted(missing)}"
        assert not extra, f"Extra keys in {locale}: {sorted(extra)}"
