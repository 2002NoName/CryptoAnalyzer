# CryptoAnalyzer – Pełna dokumentacja i instrukcja obsługi

## 1. Wprowadzenie

CryptoAnalyzer to narzędzie do analizy dysków fizycznych i obrazów dysków (RAW, EWF, VHD/VHDX) pod kątem systemów plików, szyfrowania oraz struktury katalogów. Projekt rozwijany jest w Pythonie (3.11–3.12) i oferuje zarówno interfejs wiersza poleceń (CLI), jak i graficzny interfejs użytkownika (GUI) w PySide6. Architektura modułowa umożliwia łatwe rozszerzanie o nowe sterowniki, detektory i usługi (np. integrację z API No More Ransom).

## 2. Zakres funkcjonalny

- Obsługa źródeł: dyski fizyczne (Windows/Linux/macOS) oraz obrazy (RAW/IMG/E01/VHD/VHDX).
- Obsługiwane systemy plików: NTFS, EXT4, FAT32, APFS.
- Detekcja szyfrowania: sygnatury (BitLocker, VeraCrypt, LUKS, FileVault) oraz heurystyka entropii/statystyk bajtów jako fallback.
- Analiza struktury katalogów i metadanych (nazwa, ścieżka, właściciel, rozmiar, znaczniki czasowe, atrybuty).
- Raportowanie do JSON/CSV, interaktywne drzewo w UI, eksport wyników benchmarków do JSON/Markdown.
- Benchmark modułów detekcji oraz zestaw testów jednostkowych i integracyjnych.

## 3. Wymagania środowiskowe

| Obszar              | Wymagania                                                                          |
| ------------------- | ---------------------------------------------------------------------------------- |
| System operacyjny   | Windows 10/11 (preferowany), Linux, macOS (zależnie od bibliotek niskopoziomowych) |
| Python              | 3.11 lub 3.12                                                                      |
| Menedżer zależności | Poetry ≥ 1.7                                                                       |
| Biblioteki kluczowe | pytsk3, pyewf/libewf, PySide6, structlog, pydantic                                 |
| Uprawnienia         | Dostęp tylko-do-odczytu do obrazów i dysków fizycznych                             |

## 4. Instalacja i konfiguracja

### 4.1 Przygotowanie środowiska

```bash
# klonowanie repozytorium
git clone https://example.com/CryptoAnalyzer.git
cd CryptoAnalyzer

# instalacja zależności
poetry install

# uruchomienie testów kontrolnych
poetry run pytest
```

### 4.2 Konfiguracja sygnatur szyfrowania

Plik `src/crypto_analyzer/data/encryption_signatures.json` zawiera definicje sygnatur. Dodanie nowego algorytmu polega na dopisaniu wpisu z polami: `id`, `name`, `matchers`, `offsets`, `version_extractor`. W CLI można ograniczyć używane sygnatury parametrem `--signature-id`.

### 4.3 Narzędzia pomocnicze

- Generowanie obrazów testowych Windows: `poetry run python scripts/generate_test_images_windows.py --force`
- Generowanie obrazów przez WSL2: `powershell -File scripts/generate_test_images_wsl.ps1`
- Benchmark heurystyk: `poetry run crypto-analyzer-benchmark`

## 5. Struktura projektu i architektura

### 5.1 Kluczowe katalogi

- `src/crypto_analyzer/core` – menedżer analizy, modele domenowe, kolejka zadań.
- `src/crypto_analyzer/drivers` – sterowniki TSK dla obrazów i dysków fizycznych.
- `src/crypto_analyzer/fs_detection` – wykrywanie systemów plików, mapowanie wolumenów.
- `src/crypto_analyzer/crypto_detection` – detekcja sygnaturowa i heurystyczna szyfrowania.
- `src/crypto_analyzer/metadata` – skanowanie drzew katalogów i metadanych.
- `src/crypto_analyzer/reporting` – eksport raportów JSON/CSV.
- `src/crypto_analyzer/ui` – logika interfejsu (MODELE widoku, tłumaczenia zdarzeń na operacje core).
- `src/crypto_analyzer/benchmarks` – moduł benchmarków.
- `docs/` – dokumentacja (architektura, workflow, roadmapa, dane syntetyczne).

### 5.2 Warstwowy model

```
GUI (PySide6)
  ↓
UI/VM (modele widoku, orkiestracja)
  ↓
Core/Services (AnalysisManager, SessionManager, TaskQueue)
  ↓
Warstwa analityczna (drivers | fs_detection | crypto_detection | metadata)
  ↓
Shared utilities (logowanie, konfiguracja, i18n)
```

### 5.3 Kluczowe komponenty

- `AnalysisManager` – koordynuje przebieg analizy, uruchamia detektory i eksport raportu.
- `TskImageDriver` / `TskPhysicalDiskDriver` – dostarczają zunifikowane API odczytu bloków i enumeracji wolumenów.
- `TskFileSystemDetector` – identyfikuje NTFS/EXT4/FAT32/APFS.
- `SignatureBasedDetector` i `HeuristicEncryptionDetector` – wykrywanie szyfrowania.
- `TskMetadataScanner` – rekurencyjne zbieranie metadanych.
- `DefaultReportExporter` – zapis wyników do JSON/CSV.

## 6. Przepływ działania

1. Użytkownik uruchamia aplikację (CLI/GUI) i wybiera źródło (plik obrazu lub dysk fizyczny).
2. `AnalysisManager` inicjuje sterownik TSK i enumeruje wolumeny.
3. `fs_detection` określa typ systemu plików każdego wolumenu, oznacza `UNKNOWN`, jeśli brak rozpoznania.
4. Łańcuch detektorów szyfrowania działa w kolejności: sygnatury → heurystyka fallback.
5. `metadata` skanuje katalogi (zakres zależny od ustawień GUI/CLI).
6. Postęp i logi są raportowane do UI lub stdout.
7. `reporting` generuje raport JSON/CSV oraz (opcjonalnie) metryki benchmarków.

## 7. Instrukcja obsługi (user manual)

### 7.1 Interfejs wiersza poleceń (CLI)

#### Podstawowe polecenia

```bash
# analiza pliku obrazu i zapis raportu
poetry run crypto-analyzer sample.img --output report.json

# ograniczenie do wybranych sygnatur
poetry run crypto-analyzer sample.img --signature-id bitlocker --signature-id veracrypt

# wyświetlenie pomocy
poetry run crypto-analyzer --help
```

#### Analiza dysku fizycznego

```bash
# lista dysków fizycznych
oetry run crypto-analyzer --list-devices

# analiza dysku (np. \\?\PhysicalDrive1)
poetry run crypto-analyzer --source-type physical --source "\\\\?\\PhysicalDrive1" --output drive1.json
```

**Kroki CLI:**

1. Uruchom `--list-devices`, aby sprawdzić dostępne dyski fizyczne.
2. Wskaż źródło (`--source` lub argument ścieżki obrazu).
3. (Opcjonalnie) ogranicz analizę do wybranych wolumenów (`--volume-id`).
4. Wybierz katalog wyjściowy raportu; domyślnie JSON, możesz dodać `--export csv`.
5. Śledź postęp w stdout; błędy krytyczne kończą proces kodem innym niż 0.

### 7.2 Graficzny interfejs użytkownika (GUI)

```bash
poetry run crypto-analyzer-gui
```

**Przebieg pracy:**

1. Ekran powitalny – wybierz „Obraz dysku” lub „Dysk fizyczny”.
2. W przypadku obrazu wskaż plik (obsługiwane formaty RAW/IMG/E01/VHD/VHDX). Dla dysków fizycznych aplikacja zaprezentuje listę urządzeń wykrytą przez TSK.
3. Selektor wolumenów – zaznacz wolumeny do analizy (wyświetlane są rozmiary, identyfikatory i status rozpoznania FS).
4. Rozpocznij analizę; pasek postępu pokazuje etapy (enumeracja, detekcja szyfrowania, metadane, raport).
5. Po zakończeniu zobaczysz podsumowanie (system plików, status szyfrowania, liczba znalezionych elementów).
6. Użyj przycisków „Eksport JSON” lub „Eksport CSV”, aby zapisać wyniki. GUI przechowuje ostatnią lokalizację zapisu.
7. Wersja MVP wykonuje szybki skan (głębokość 0) dla responsywności; pełne drzewo planowane jest według roadmapy.

### 7.3 Benchmarki i ocena jakości

```bash
# uruchomienie pełnych benchmarków
poetry run crypto-analyzer-benchmark

# benchmark z dodatkowymi obrazami FS
oetry run crypto-analyzer-benchmark --images-dir test_assets/generated
```

Wyniki zapisują się domyślnie w `benchmark_reports/benchmark_report.json` oraz `benchmark_reports/benchmark_report.md`. Sekcje raportu obejmują: `signature_magic_bytes`, `heuristic_encryption`, `filesystem_detection` (opcjonalnie).

### 7.4 Generowanie danych syntetycznych

- Testy jednostkowe (Poziom A) korzystają z generatorów w `tests/synthetic_data.py`.
- Mini-obrazy (Poziom B) tworzy się skryptami z `scripts/` lub `test_assets/wsl/`. Po wygenerowaniu obrazów uruchom `poetry run pytest tests/test_integration_generated_images.py`.

### 7.5 Interpretacja raportów

Raport JSON zawiera hierarchię: `source -> volumes -> directories -> files`. Każdy wolumen ma pola `filesystem`, `encryption.status`, `encryption.algorithm`, `encryption.confidence`. Dodatkowa sekcja `artifacts` (planowana) będzie raportować kontenery szyfrowane wykryte jako pliki.

## 8. Testy i zapewnienie jakości

- `pytest` – pełny zestaw testów jednostkowych (CLI, GUI, detektory, TSK driver).
- `pytest-qt` – testy komponentów GUI (gdzie dotyczy).
- Benchmark entropii – macierz pomyłek 3-klasowa (`ENCRYPTED`, `NOT_DETECTED`, `UNKNOWN`).
- Kryteria jakości: brak crashy na wolumenach `UNKNOWN FS`, niski współczynnik FP dla heurystyki, możliwość pominięcia heurystyki (`--skip-heuristics`) w trybie inwentaryzacji.

## 9. Plan rozwoju (wyciąg z roadmapy)

- Rozszerzenie sterowników o kolejne systemy plików i kontenery.
- Pełne drzewo katalogów w GUI wraz z filtrowaniem wyników.
- Wykrywanie kontenerów szyfrowanych jako plików w rozpoznanym FS.
- Integracja z API No More Ransom poprzez abstrakcję `CryptoAdvisoryService`.
- Eksport dodatkowych formatów (PDF), pakiety instalacyjne (Windows installer, AppImage).
- Lokalizacja PL/EN oraz poprawa dostępności UI.

## 10. Rozwiązywanie problemów

| Problem                                                  | Rozwiązanie                                                                                                                                                                               |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pytsk3` nie ładuje sterownika                           | Upewnij się, że biblioteka jest skompilowana dla Twojej architektury; na Windows wymagane są pakiety Visual C++ Redistributable.                                                          |
| Brak dostępu do dysku fizycznego                         | Uruchom powłokę z uprawnieniami administratora lub nadaj odpowiednie uprawnienia urządzeniom blokowym.                                                                                    |
| Benchmark `filesystem_detection` pomija test             | Sprawdź, czy istnieje `test_assets/generated/multi_volume.img` i czy skrypt generujący zakończył się sukcesem.                                                                            |
| GUI nie wyświetla dysków                                 | Zweryfikuj, czy TSK widzi urządzenia (polecenie CLI `--list-devices`).                                                                                                                    |
| Raport zawiera status `UNKNOWN` dla wszystkich wolumenów | Sprawdź, czy obraz nie jest zaszyfrowany całkowicie lub uszkodzony; w razie potrzeby zwiększ zakres skanowania (planowana opcja) lub przeprowadź analizę heurystyczną na większej próbce. |

## 11. Odniesienia

- Dokument architektury: `docs/architecture.md`
- Przepływ pracy i scenariusze: `docs/workflow.md`
- Roadmapa projektu: `docs/roadmap.md`
- Dane syntetyczne i benchmarki: `docs/synthetic_data.md`
- Testy i przykłady: `tests/` (szczególnie `tests/synthetic_data.py`)

Dokument zostanie aktualizowany wraz z rozwojem projektu i powinien być traktowany jako centralne źródło informacji użytkownika oraz dewelopera.
