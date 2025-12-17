"""Proste zarządzanie lokalizacją tekstów interfejsu użytkownika."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping


_TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "pl": {
        "app.title": "CryptoAnalyzer",
        "app.description": (
            "Narzędzie do analizy dysków i obrazów dysków\n"
            "pod kątem szyfrowania oraz struktury plików"
        ),
        "button.physical": "Dysk fizyczny",
        "button.image": "Obraz dysku",
        "button.export.json": "Eksportuj JSON",
        "button.export.csv": "Eksportuj CSV",
        "checkbox.metadata": "Zbieraj metadane plików (wolniejsze)",
        "label.depth": "Głębokość skanowania:",
        "label.depth.unlimited": "Bez limitu",
        "label.workers": "Wątki:",
        "label.status.ready": "Gotowy do analizy.",
        "status.driver.unavailable": "Sterownik TSK nie jest dostępny w tym środowisku.",
        "dialog.select.physical.title": "Wybierz dysk fizyczny",
        "dialog.select.physical.prompt": "Dostępne dyski:",
        "dialog.select.physical.none": "Nie wykryto żadnych dysków fizycznych lub brak uprawnień.",
        "dialog.select.physical.no_access": "Brak dostępu do dysków fizycznych.",
        "dialog.select.image.title": "Wybierz obraz dysku",
        "dialog.select.volumes.title": "Wybierz wolumeny do analizy",
        "dialog.select.volumes.description": "Zaznacz wolumeny przeznaczone do analizy:",
        "dialog.analyze.title": "Wyniki analizy",
        "dialog.analyze.cancelled": "Analiza anulowana przez użytkownika.",
        "dialog.analyze.no_volumes": "Nie wykryto żadnych wolumenów do analizy.",
        "dialog.analyze.no_selection": "Nie wybrano wolumenów do analizy.",
        "dialog.analyze.no_sources": "Sterownik nie zwrócił żadnych źródeł do analizy.",
        "dialog.analyze.error": "Analiza zakończyła się błędem:",
        "dialog.report.no_results": "Najpierw uruchom analizę źródła danych.",
        "dialog.report.error": "Nie udało się zapisać raportu:",
        "dialog.report.saved": "Raport zapisano w:",
        "dialog.report.title": "Zapisz raport",
        "dialog.report.filter.json": "Pliki JSON (*.json)",
        "dialog.report.filter.csv": "Pliki CSV (*.csv)",
        "dialog.elevation.required": "Aby uzyskać dostęp do dysków fizycznych, uruchom aplikację jako administrator.",
        "dialog.elevation.button": "Uruchom ponownie jako administrator",
        "dialog.elevation.failed": "Nie udało się uruchomić aplikacji z podniesionymi uprawnieniami.",
        "dialog.metadata.skipped": "Metadane pominięte",
        "dialog.progress.cancel": "Przerwij",
        "dialog.bitlocker.unlock.title": "Odszyfruj BitLocker",
        "dialog.bitlocker.unlock.prompt": "Wolumen {identifier} wygląda na zaszyfrowany. Podaj klucz odzyskiwania BitLocker (lub pozostaw puste, aby pominąć odszyfrowanie):",
        "dialog.bitlocker.method.title": "Odblokowanie BitLocker",
        "dialog.bitlocker.method.prompt": "Wolumen {identifier} wygląda na zaszyfrowany. Wybierz metodę odblokowania:",
        "dialog.bitlocker.method.recovery_key": "Klucz odzyskiwania (Recovery Key)",
        "dialog.bitlocker.method.password": "Hasło",
        "dialog.bitlocker.method.startup_key": "Startup key (plik)",
        "dialog.bitlocker.method.skip": "Pomiń odblokowanie",
        "dialog.bitlocker.password.title": "Hasło BitLocker",
        "dialog.bitlocker.password.prompt": "Podaj hasło dla wolumenu {identifier} (lub pozostaw puste, aby pominąć):",
        "dialog.bitlocker.startup_key.title": "Startup key BitLocker",
        "dialog.bitlocker.startup_key.prompt": "Wskaż plik startup key dla wolumenu {identifier}.",
        "dialog.filevault2.password.title": "Hasło FileVault2",
        "dialog.filevault2.password.prompt": "Podaj hasło dla wolumenu {identifier} (lub pozostaw puste, aby pominąć):",
        "filesystem.unknown": "Nieznany",
        "filesystem.encrypted": "Szyfrowany wolumen",
        "filesystem.partially_encrypted": "Częściowo szyfrowany wolumen",
        "dialog.unknown_fs.title": "Nieznany system plików",
        "dialog.unknown_fs.message": "Wolumen {identifier} ma nieznany system plików. Pominąć go i kontynuować analizę?",
        "dialog.unknown_fs.skip": "Pomiń wolumen",
        "dialog.unknown_fs.abort": "Przerwij analizę",
        "dialog.unknown_fs.no_remaining": "Nie pozostały żadne wolumeny do analizy.",
        "dialog.unknown_fs.skipping": "Pomijam wolumen {identifier}...",
        "progress.preparing": "Przygotowanie analizy...",
        "progress.running": "Analiza w toku...",
        "progress.cancelling": "Anulowanie analizy...",
        "status.analysis.completed": "Analiza {description} zakończona pomyślnie.",
        "status.analysis.failed": "Analiza zakończyła się błędem.",
        "status.analysis.cancelled": "Analiza anulowana.",
        "column.name": "Nazwa",
        "column.type": "Typ",
        "column.size": "Rozmiar",
        "column.encryption": "Szyfrowanie",
        "column.details": "Szczegóły",
        "tree.volume": "wolumen ({filesystem})",
        "tree.metadata_skipped": "Metadane pominięte",
        "tree.directory": "katalog",
        "tree.file": "plik",
        "language.label": "Język:",
        "language.polish": "Polski",
        "language.english": "English",
        "summary.source": "Źródło: {display_name}",
        "summary.volume": "- {identifier}: FS={filesystem}, szyfrowanie={encryption} (algorytm: {algorithm})",
        "summary.totals.volumes": "Łączna liczba wolumenów: {count}",
        "summary.totals.files": "Łączna liczba plików: {count}",
        "summary.totals.directories": "Łączna liczba katalogów: {count}",
        "summary.metadata.enabled": "Metadane plików: tak",
        "summary.metadata.disabled": "Metadane plików: nie",
    },
    "en": {
        "app.title": "CryptoAnalyzer",
        "app.description": (
            "Disk and image analysis tool\n"
            "for encryption and file structure"
        ),
        "button.physical": "Physical Disk",
        "button.image": "Disk Image",
        "button.export.json": "Export JSON",
        "button.export.csv": "Export CSV",
        "checkbox.metadata": "Collect file metadata (slower)",
        "label.depth": "Scan depth:",
        "label.depth.unlimited": "No limit",
        "label.workers": "Workers:",
        "label.status.ready": "Ready for analysis.",
        "status.driver.unavailable": "TSK driver is not available in this environment.",
        "dialog.select.physical.title": "Select physical disk",
        "dialog.select.physical.prompt": "Available disks:",
        "dialog.select.physical.none": "No physical disks detected or insufficient permissions.",
        "dialog.select.physical.no_access": "No access to physical disks.",
        "dialog.select.image.title": "Choose disk image",
        "dialog.select.volumes.title": "Select volumes for analysis",
        "dialog.select.volumes.description": "Mark the volumes to analyze:",
        "dialog.analyze.title": "Analysis results",
        "dialog.analyze.cancelled": "Analysis cancelled by user.",
        "dialog.analyze.no_volumes": "No volumes detected for analysis.",
        "dialog.analyze.no_selection": "No volumes selected for analysis.",
        "dialog.analyze.no_sources": "Driver did not return any sources for analysis.",
        "dialog.analyze.error": "Analysis finished with an error:",
        "dialog.report.no_results": "Run the analysis first.",
        "dialog.report.error": "Failed to save report:",
        "dialog.report.saved": "Report saved to:",
        "dialog.report.title": "Save report",
        "dialog.report.filter.json": "JSON files (*.json)",
        "dialog.report.filter.csv": "CSV files (*.csv)",
        "dialog.elevation.required": "Administrator privileges are required to access physical disks.",
        "dialog.elevation.button": "Restart as Administrator",
        "dialog.elevation.failed": "Could not relaunch the application with elevated privileges.",
        "dialog.metadata.skipped": "Metadata skipped",
        "dialog.progress.cancel": "Cancel",
        "dialog.bitlocker.unlock.title": "Unlock BitLocker",
        "dialog.bitlocker.unlock.prompt": "Volume {identifier} appears encrypted. Enter the BitLocker recovery key (or leave blank to skip unlocking):",
        "dialog.bitlocker.method.title": "BitLocker Unlock",
        "dialog.bitlocker.method.prompt": "Volume {identifier} appears encrypted. Choose an unlock method:",
        "dialog.bitlocker.method.recovery_key": "Recovery key",
        "dialog.bitlocker.method.password": "Password",
        "dialog.bitlocker.method.startup_key": "Startup key (file)",
        "dialog.bitlocker.method.skip": "Skip unlocking",
        "dialog.bitlocker.password.title": "BitLocker Password",
        "dialog.bitlocker.password.prompt": "Enter the password for volume {identifier} (or leave blank to skip):",
        "dialog.bitlocker.startup_key.title": "BitLocker Startup Key",
        "dialog.bitlocker.startup_key.prompt": "Select the startup key file for volume {identifier}.",
        "dialog.filevault2.password.title": "FileVault2 Password",
        "dialog.filevault2.password.prompt": "Enter the password for volume {identifier} (or leave blank to skip):",
        "filesystem.unknown": "Unknown",
        "filesystem.encrypted": "Encrypted volume",
        "filesystem.partially_encrypted": "Partially encrypted volume",
        "dialog.unknown_fs.title": "Unknown filesystem",
        "dialog.unknown_fs.message": "Volume {identifier} uses an unknown filesystem. Skip it and continue?",
        "dialog.unknown_fs.skip": "Skip volume",
        "dialog.unknown_fs.abort": "Abort analysis",
        "dialog.unknown_fs.no_remaining": "No volumes left to analyze.",
        "dialog.unknown_fs.skipping": "Skipping volume {identifier}...",
        "progress.preparing": "Preparing analysis...",
        "progress.running": "Analysis in progress...",
        "progress.cancelling": "Cancelling analysis...",
        "status.analysis.completed": "Analysis of {description} finished successfully.",
        "status.analysis.failed": "Analysis ended with an error.",
        "status.analysis.cancelled": "Analysis cancelled.",
        "column.name": "Name",
        "column.type": "Type",
        "column.size": "Size",
        "column.encryption": "Encryption",
        "column.details": "Details",
        "tree.volume": "volume ({filesystem})",
        "tree.metadata_skipped": "Metadata skipped",
        "tree.directory": "directory",
        "tree.file": "file",
        "language.label": "Language:",
        "language.polish": "Polish",
        "language.english": "English",
        "summary.source": "Source: {display_name}",
        "summary.volume": "- {identifier}: FS={filesystem}, encryption={encryption} (algorithm: {algorithm})",
        "summary.totals.volumes": "Total volumes: {count}",
        "summary.totals.files": "Total files: {count}",
        "summary.totals.directories": "Total directories: {count}",
        "summary.metadata.enabled": "File metadata: yes",
        "summary.metadata.disabled": "File metadata: no",
    },
}


@dataclass(slots=True)
class LocalizationManager:
    """Eksponuje teksty interfejsu w zależności od wybranego języka."""

    locale: str = "pl"

    def set_locale(self, locale: str) -> None:
        if locale not in _TRANSLATIONS:
            raise ValueError(f"Unsupported locale: {locale}")
        self.locale = locale

    def text(self, key: str) -> str:
        table = _TRANSLATIONS.get(self.locale, _TRANSLATIONS["pl"])
        try:
            return table[key]
        except KeyError as exc:
            raise KeyError(f"Missing translation for key '{key}' in locale '{self.locale}'") from exc

    def available_locales(self) -> Mapping[str, str]:
        return {
            "pl": _TRANSLATIONS["pl"]["language.polish"],
            "en": _TRANSLATIONS["en"]["language.english"],
        }


__all__ = ["LocalizationManager"]
