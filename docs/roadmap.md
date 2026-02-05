# Roadmap CryptoAnalyzer

## Faza 0 – Przygotowanie

- Ustalenie wymagań funkcjonalnych i niefunkcjonalnych.
- Analiza licencji zależności (pytsk3, pyewf, libfsntfs, libfsapfs, PySide6).
- Przygotowanie środowiska developerskiego (poetry/uv, pre-commit, ruff, mypy).
- Stworzenie repozytorium z bazową strukturą modułów i CI (GitHub Actions).

## Faza 1 – Rdzeń analityczny

- Implementacja `drivers` z obsługą obrazów RAW i dysków fizycznych (Windows/Linux).
- Obsługa systemów plików NTFS i FAT32 przy użyciu `pytsk3`.
- Moduł `fs_detection` – identyfikacja wolumenów i przypisanie typów FS.
- Podstawowe modele danych i menedżer zadań w `core`.
- Prosty interfejs CLI do uruchamiania analiz.

## Faza 2 – Wykrywanie szyfrowania

- Moduł `crypto_detection` z heurystykami dla BitLocker i VeraCrypt (konfigurowalne sygnatury).
- Integracja z wynikami `fs_detection`, raportowanie statusu wolumenów.
- Rozszerzenie `drivers` o wsparcie EXT4 i APFS.
- Testy integracyjne na wzorcowych obrazach.

## Faza 3 – Analiza metadanych

- Implementacja rekurencyjnego skanera katalogów (`metadata`).
- Zbieranie metadanych (nazwa, właściciel, daty, rozmiar, atrybuty, status szyfrowania).
- Optymalizacja wydajności (praca wielowątkowa, kolejka zadań).
- Walidacja danych i raportów JSON/CSV.

## Faza 4 – GUI

- Prototyp interfejsu w PySide6: ekran startowy, wybór źródła, selektor wolumenów, eksport raportów.
- Implementacja MVVM i integracja z warstwą `core` przez API usług.
- Obsługa przetwarzania w tle i postępu w UI.
- Lokalizacja (PL/EN) i testy użyteczności.

## Faza 5 – Stabilizacja i rozszerzenia

- Dane syntetyczne i ocena jakości heurystyk (WSL2):
    - zestaw generatorów danych Poziomu A (bufory bajtów) + deterministyczne testy jednostkowe,
    - skrypty generujące mini-obrazy Poziomu B w WSL2 + manifest „ground truth” dla testów integracyjnych,
    - benchmark heurystyki (offline) z metrykami: macierz pomyłek (3 klasy), precision/recall dla `ENCRYPTED`, FP-rate na koszyku „pułapki”,
    - kryteria akceptacji: brak crasha na `UNKNOWN FS`, bardzo niski FP dla `ENCRYPTED`, przypadki niejednoznaczne klasyfikowane jako `UNKNOWN`.
- Wykrywanie kontenerów szyfrowanych jako pliki (np. VeraCrypt) na wolumenach z rozpoznanym FS:
    - skanowanie plików pod kątem sygnatur nagłówków kontenerów (nie mylić ze statusem szyfrowania całego wolumenu),
    - raportowanie „podejrzanych plików” w wynikach (osobna sekcja/atrybut, niezależny od `Volume.encryption`),
    - testy: Poziom A (bufory z nagłówkiem kontenera) + Poziom B (mini-obraz FS z plikiem-kontenerem),
    - kryteria akceptacji: kontener wykryty jako artefakt plikowy bez podnoszenia statusu szyfrowania wolumenu.
- Integracja z API No More Ransom (jeśli dostępne) lub przygotowanie abstrakcji.
- Dodanie eksportu do dodatkowych formatów (np. PDF) – opcjonalnie.
- Finalizacja dokumentacji użytkownika i dewelopera (częściowa – README/workflow aktualizowane na bieżąco).
- Przygotowanie pakietu instalacyjnego (installer Windows, AppImage).

## Ciągłe działania

- Testy regresyjne i rozszerzanie zestawu próbek.
- Monitorowanie bezpieczeństwa zależności (Dependabot).
- Analiza feedbacku i planowanie kolejnych wydań.
