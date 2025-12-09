# Architektura CryptoAnalyzer

## Przegląd

Aplikacja ma warstwową, modularną architekturę, umożliwiającą łatwe rozszerzanie i wymianę poszczególnych komponentów. Rdzeń systemu stanowi zestaw usług analitycznych, a interfejs graficzny (PySide6) działa jako cienki klient, komunikujący się poprzez warstwę modeli widoku (MVVM).

```
┌──────────┐
│   GUI    │  PySide6, MVVM
└────┬─────┘
     │
┌────▼────┐
│  UI/VM  │  Modele widoku, orkiestracja zadań
└────┬────┘
     │
┌────▼─────────────────────────────────────┐
│                Core/Services             │
│  Zadania analizy, menedżer sesji, logika │
└────┬─────────────────────────────────────┘
     │
┌────▼───────────────────────────────────────────────────┐
│           Warstwa analityczna (moduły)                 │
│ drivers | fs_detection | crypto_detection | metadata   │
└────┬───────────────────────────────────────────────────┘
     │
┌────▼────────────────┐
│   Shared Utilities  │  logowanie, konfiguracja, i18n
└─────────────────────┘
```

## Moduły pakietu `crypto_analyzer`

-   `core` – definicje modeli domenowych (dysk, wolumen, katalog, plik, raport), mechanizm kolejki zadań, menedżer analizy, współdzielone protokoły dla usług.
-   `drivers` – adaptery źródeł danych: obrazy dysków (EWF, RAW), dyski fizyczne, integracja z `pytsk3`, `pyewf`, `libfsntfs`, `libfsapfs` itp. Zapewnia zunifikowane API dla warstwy `core`.
-   `fs_detection` – heurystyki i logika rozpoznawania systemów plików, wykrywanie wolumenów, mapowanie offsetów.
-   `crypto_detection` – moduły wykrywające szyfrowanie (BitLocker, VeraCrypt, LUKS, FileVault) oraz określające wersję/parametry, wykorzystujące sygnatury i analizę nagłówków.
-   `metadata` – rekurencyjne skanowanie drzewa katalogów i zbieranie metadanych (daty, właściciel, rozmiar, sumy kontrolne opcjonalnie).
-   `reporting` – generowanie raportów CSV/JSON, API raportowania do warstwy UI.
-   `ui` – logika specyficzna dla interfejsu; modele widoku, formatowanie danych, translator zdarzeń użytkownika na operacje `core`.
-   `shared` – logowanie (`structlog`), konfiguracja, internacjonalizacja, narzędzia wspólne.

### Implementacje referencyjne (MVP)

-   `core.AnalysisManager` – orkiestruje przebieg analizy, wywołuje detektory systemów plików i szyfrowania, inicjuje eksport raportu.
-   `drivers.TskImageDriver` – sterownik `pytsk3` dla obrazów dysków (RAW/E01/VHD), udostępnia wolumeny oraz surowy odczyt.
-   `fs_detection.TskFileSystemDetector` – identyfikuje NTFS/EXT4/FAT32/APFS na podstawie uchwytu TSK.
-   `metadata.TskMetadataScanner` – rekurencyjny zczyt drzewa katalogów i metadanych poprzez `pytsk3`.
-   `crypto_detection.SignatureBasedDetector` – ogólny detektor oparty na sygnaturach z pliku `src/crypto_analyzer/data/encryption_signatures.json`.
-   `crypto_detection.BitLockerDetector` – wariant korzystający z sygnatury BitLocker (`-FVE-FS-`) z konfiguracji.
-   `reporting.DefaultReportExporter` – eksport wyników analizy do JSON/CSV z zachowaniem struktury drzewa.

## Wzorce i konwencje

-   **MVVM** dla UI: widoki (QML/Qt Widgets) komunikują się z warstwą `ui` (modele widoku); logika biznesowa pozostaje w `core`.
-   **Dependency Injection**: moduły `drivers`, `fs_detection`, `crypto_detection` rejestrowane w kontenerze usług, co ułatwia testowanie i wymianę komponentów.
-   **Asynchroniczność**: długotrwałe zadania wykonywane w tle (asyncio + wątki robocze) z przekazywaniem postępu do UI.
-   **Konwencje kodu**: `ruff`/`black` (styl), `mypy` (typowanie), dokstringi typu Google, logowanie strukturalne.

## Komponenty zewnętrzne

-   `pytsk3` – analiza systemów plików i wolumenów.
-   `pyewf` / `libewf` – obsługa obrazów EnCase.
-   `cryptography`, `pyAesCrypt`, `python-bitcoinlib` (opcjonalnie) – heurystyki szyfrowania.
-   `structlog`, `pydantic`/~`pydantic-core` – walidacja danych.
-   `PySide6` – GUI.

## Integracja API No More Ransom (future-proof)

Warstwa `core` zostanie zaprojektowana z myślą o potencjalnej integracji z usługami zewnętrznymi. Interfejs `CryptoAdvisoryService` pozwoli dodawać moduły konsultujące próbki z API No More Ransom, bez ingerencji w resztę kodu.

## Środowisko testowe

-   `pytest` – testy jednostkowe i integracyjne.
-   `pytest-qt` – testy widoków.
-   Próbki obrazów testowych przechowywane lokalnie w katalogu `test_assets/` (niesynchronizowanym z repozytorzem produkcyjnym).

## Skalowalność i przyszłe rozszerzenia

-   Dodawanie kolejnych systemów plików poprzez nowe sterowniki w `drivers` i heurystyki w `fs_detection`.
-   Wprowadzenie modułu `forensics` do głębszej analizy (np. timeline, carwing) – zachowujemy neutralne interfejsy.
-   Możliwość uruchomienia w trybie CLI (oddzielny entry-point) dzięki wyodrębnieniu logiki z warstwy UI.
