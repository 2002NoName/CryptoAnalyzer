# CryptoAnalyzer

Narzędzie do analizy dysków oraz obrazów dysków pod kątem szyfrowania, struktury katalogów i metadanych plików. Projekt rozwijany w Pythonie z graficznym interfejsem (PySide6) i modularną architekturą.

## Kluczowe funkcje

-   Wykrywanie typu źródła: dysk fizyczny lub obraz (RAW, EWF, VHD/X).
-   Obsługa systemów plików: NTFS, EXT4, FAT32, APFS.
-   Identyfikacja szyfrowania (BitLocker, VeraCrypt, LUKS, FileVault) i jego parametrów.
-   Analiza drzew katalogów i metadanych (nazwa, właściciel, rozmiar, daty, atrybuty).
-   Prezentacja wyników w formie interaktywnego drzewa oraz eksport raportów CSV/JSON.

## Struktura projektu

-   `docs/` – dokumentacja techniczna, architektura, roadmapa.
-   `src/crypto_analyzer/` – kod źródłowy aplikacji (moduły opisane w dokumentacji).
-   `tests/` – testy jednostkowe i integracyjne (placeholder).

## Rozpoczęcie pracy

-   [Poetry](https://python-poetry.org/docs/#installation) ≥ 1.7
-   Python 3.11 lub 3.12

Polecenia podstawowe:

```bash
poetry install
poetry run pytest
```

### Uruchomienie aplikacji

**Interfejs wiersza poleceń (CLI):**

```bash
poetry run crypto-analyzer image.img --output report.json
poetry run crypto-analyzer --help
```

**Graficzny interfejs użytkownika (GUI):**

```bash
poetry run crypto-analyzer-gui
```

Szczegóły projektowe znajdują się w katalogu `docs/`.
