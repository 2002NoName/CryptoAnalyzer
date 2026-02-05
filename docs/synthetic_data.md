# Dane syntetyczne: generowanie, testowanie i ocena

Ten dokument opisuje strategię tworzenia danych syntetycznych do testów CryptoAnalyzer oraz sposób testowania i oceny jakości wykrywania (w szczególności: wykrywanie szyfrowania wolumenów bez rozpoznanego systemu plików oraz kontenerów szyfrowanych jako plików).

## Cele

- Zapewnić szybkie, deterministyczne testy jednostkowe dla logiki detekcji (bez zależności od TSK).
- Zapewnić testy integracyjne, które weryfikują cały pipeline (TSK → detekcja → skan metadanych → raport).
- Ustalić mierzalny sposób oceny heurystyk (trade-off false positive vs false negative).

## Dwa poziomy danych testowych

### Poziom A — dane bajtowe (unit tests)

W tym poziomie testujemy moduły detekcji na kontrolowanych danych wejściowych (bufory `bytes`) i stubowanych driverach.

Zastosowania:

- `crypto_detection.SignatureBasedDetector` (sygnatury / magic bytes).
- `crypto_detection.HeuristicEncryptionDetector` (entropia i statystyki bajtów).
- stabilność (błędy odczytu, za mała próbka, brak rozmiaru wolumenu itp.).

Korzyści:

- bardzo szybkie testy,
- deterministyczne,
- brak zależności środowiskowych.

### Poziom B — mini-obrazy dysków/partycji (integration tests)

W tym poziomie testujemy integrację z TSK i realistyczny przebieg analizy.

Zastosowania:

- `drivers` + `fs_detection` + `metadata` + `reporting`.
- odporność na „trudne” wolumeny (UNKNOWN FS, partycje RAW/unformatted, uszkodzone struktury).

Korzyści:

- weryfikacja pipeline end-to-end,
- większa wiarygodność niż same bufory bajtów.

Koszty:

- wolniejsze,
- zależne od środowiska (dlatego preferujemy generację w WSL2).

## Generowanie danych (Poziom A)

### Narzędzia w repo

- [tests/synthetic_data.py](tests/synthetic_data.py) – deterministyczne generatory bajtów i prosty `InMemoryDriver` do uruchamiania detektorów na buforach.
- `crypto-analyzer-benchmark` – uruchamia zestaw benchmarków i generuje raport w JSON/Markdown (patrz niżej).
- [scripts/benchmark_heuristics.py](scripts/benchmark_heuristics.py) – wrapper zgodności (deleguje do modułu benchmarków).

### 1) Dane do testów sygnaturowych

Tworzymy bufor o znanym rozmiarze (np. 1–8 MiB) i wstrzykujemy sygnatury w kontrolowanych offsetach:

- offset `0` (początek wolumenu),
- offset `512` (typowe wyrównanie sektorowe),
- offset `4096` (wyrównanie stron),
- „środek” i „koniec - N”.

Warianty testowe:

- pełny match,
- brak match,
- „prawie match” (1 bajt inny),
- konflikt (dwie sygnatury pasują; testujemy kolejność/prioritet wg konfiguracji),
- sygnatura w innym offset niż oczekiwany (powinno nie zadziałać).

### 2) Dane do testów heurystyki (entropia)

Heurystyka powinna być oceniana jak klasyfikator z priorytetem niskiego FP.

Koszyki danych:

- **Encrypted-like**: deterministyczne „losowe” bajty (seed) → wysoka entropia.
- **Not-encrypted-like**:
    - wypełnienie zerami,
    - wypełnienie jednym bajtem,
    - dane ASCII,
    - dane o małej liczbie symboli.
- **Pułapki (high entropy, ale nie szyfrowanie)**:
    - dane skompresowane,
    - multimedia,
    - archiwa.

Warianty próbkujące (zgodne z aktualną implementacją czytania start/mid/end):

- start losowy, środek zera, koniec losowy,
- start zera, środek losowy, koniec zera,
- wszystkie trzy fragmenty wysokiej entropii.

### 3) Stabilność i odporność

Przykładowe przypadki:

- próbka krótsza niż `min_sample_size` → wynik `UNKNOWN`,
- driver zgłasza błąd odczytu dla fragmentu środkowego → brak crasha, wynik `UNKNOWN`,
- rozmiar wolumenu `0` / `None` / bardzo mały,
- wolumen ma rozpoznany FS → heurystyka nie powinna zwracać `ENCRYPTED`.

## Generowanie danych (Poziom B) w WSL2

### Założenie środowiskowe

Testy integracyjne generujemy i uruchamiamy przez WSL2 (Linux userspace) ze względu na dostępność narzędzi typu `dd`, `parted`, `mkfs.*`.

Rekomendacja:

- generować obrazy w CI i lokalnie przez WSL2,
- nie commitować ciężkich binariów do repo; zamiast tego trzymać skrypty generujące + manifest „ground truth”.

### Minimalny zestaw scenariuszy integracyjnych

1. Obraz wielowolumenowy (2–3 wolumeny):

- wolumen z poprawnym FS i kilkoma plikami/katalogami (test `metadata`),
- wolumen RAW/unformatted (test „brak crasha”, `UNKNOWN FS`),
- wolumen z blobem wysokiej entropii bez FS (test heurystyki na „wolumenie zaszyfrowanym”).

2. Obraz edge-case:

- przycięty/uszkodzony obraz,
- wolumen z FS, ale błąd odczytu w trakcie skanowania metadanych (test „nie zabijaj całej analizy”).

## Kontenery szyfrowane jako plik (VeraCrypt container w FS)

Założenie funkcjonalne: poza „wolumenem bez FS” chcemy też wykrywać kontenery szyfrowane jako pliki znajdujące się w systemie plików (np. plik `.hc`, `.tc`, plik bez rozszerzenia).

Proponowana strategia testów:

- Poziom A: detektor „file container” działa na buforze bajtów z nagłówkiem kontenera.
- Poziom B: mini-obraz FS zawierający plik-kontener; w raporcie oznaczamy plik jako podejrzany (wymaga osobnej funkcji/feature w aplikacji).

Uwaga: to rozróżnienie jest ważne, bo kontener jako plik nie powinien wpływać na status szyfrowania całego wolumenu.

## Testowanie i ocena jakości

### Testy automatyczne (CI)

- Unit:
    - sprawdzamy dokładne `EncryptionStatus` (`ENCRYPTED`/`NOT_DETECTED`/`UNKNOWN`),
    - sprawdzamy stabilność (brak wyjątków),
    - dla sygnatur: poprawne `algorithm`, `version`, `details`.
- Integration:
    - analiza wielu wolumenów nie crashuje na `UNKNOWN FS`,
    - metadane są zbierane tylko dla wolumenów czytelnych jako-is,
    - raport ma spójne liczniki (pliki/katalogi),
    - eksport działa w JSON/CSV.

### Ocena heurystyki (offline benchmark)

Heurystyka entropii ma naturalne FP w danych skompresowanych. Dlatego:

- priorytetem jest niski **False Positive Rate** dla klasy `ENCRYPTED`,
- przypadki niejednoznaczne powinny lądować w `UNKNOWN` (to jest akceptowalne w triage/DFIR).

Metryki:

- macierz pomyłek (3-klasowa: `ENCRYPTED`/`NOT_DETECTED`/`UNKNOWN`),
- precision/recall dla `ENCRYPTED`,
- FP rate na koszyku „pułapki”.

Proces strojenia progów:

- iteracyjnie modyfikujemy progi w `HeuristicConfig`,
- benchmark uruchamiamy na stałym zbiorze próbek (z ustalonym seedem),
- dokumentujemy wyniki (tabela + wnioski) i zamrażamy progi na potrzeby wydania.

Uruchamianie benchmarku:

```bash
poetry run crypto-analyzer-benchmark
```

Wyniki:

- domyślnie zapis do katalogu `benchmark_reports/` jako `benchmark_report.json` i `benchmark_report.md`

Benchmarki w raporcie obejmują:

- `signature_magic_bytes` – walidacja sygnatur z konfiguracji (magic bytes) na syntetycznych buforach,
- `heuristic_encryption` – ocena heurystyki entropii na syntetycznych buforach,
- `filesystem_detection` – opcjonalnie: test detekcji FS na wygenerowanym obrazie (wymaga pliku `multi_volume.img`).

Generowanie obrazu `multi_volume.img`:

- Windows (bez WSL2): `poetry run python scripts/generate_test_images_windows.py --force`
- WSL2: patrz sekcja poniżej (generator + wrapper)

Jeśli chcesz uruchomić benchmark detekcji systemu plików, wskaż katalog z wygenerowanymi obrazami:

```bash
poetry run crypto-analyzer-benchmark --images-dir test_assets/generated
```

## Definicja „sukcesu” w projekcie

- `ENCRYPTED`: tylko przy silnym, powtarzalnym sygnale (niski FP).
- `UNKNOWN`: domyślna odpowiedź, gdy nie ma pewności.
- `NOT_DETECTED`: gdy mamy sensowny sygnał, że dane są czytelne (np. FS wykryty) lub próbka ma bardzo niską zmienność.

## Generowanie obrazów testowych (WSL2 / Windows) – stan implementacji

W repo jest gotowy szkielet Poziomu B do generowania obrazów i opcjonalny test integracyjny.

- Generator (WSL2): [test_assets/wsl/generate_images.sh](test_assets/wsl/generate_images.sh)
- Wrapper (Windows → WSL2): [scripts/generate_test_images_wsl.ps1](scripts/generate_test_images_wsl.ps1)
- Generator (Windows, bez WSL2): [scripts/generate_test_images_windows.py](scripts/generate_test_images_windows.py)
- Test opcjonalny: [tests/test_integration_generated_images.py](tests/test_integration_generated_images.py)

Uruchomienie (Windows):

Wariant A (bez WSL2, pure Python):

```powershell
poetry run python scripts/generate_test_images_windows.py --force
```

Wariant B (WSL2):

```powershell
powershell -File scripts/generate_test_images_wsl.ps1
```

Wynik:

- obraz: `test_assets/generated/multi_volume.img`

Odpalenie testów:

```bash
poetry run pytest
```

Uwaga: test integracyjny jest oznaczony jako opcjonalny (skip), jeśli nie ma prawdziwego `pytsk3` lub brak wygenerowanego obrazu.
