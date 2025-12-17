# Roadmap CryptoAnalyzer

## Faza 0 – Przygotowanie (Tydzień 1)

-   Ustalenie wymagań funkcjonalnych i niefunkcjonalnych.
-   Analiza licencji zależności (pytsk3, pyewf, libfsntfs, libfsapfs, PySide6).
-   Przygotowanie środowiska developerskiego (poetry/uv, pre-commit, ruff, mypy).
-   Stworzenie repozytorium z bazową strukturą modułów i CI (GitHub Actions).

## Faza 1 – Rdzeń analityczny (Tygodnie 2–5)

-   Implementacja `drivers` z obsługą obrazów RAW i dysków fizycznych (Windows/Linux) ✅.
-   Obsługa systemów plików NTFS i FAT32 przy użyciu `pytsk3` ✅.
-   Moduł `fs_detection` – identyfikacja wolumenów i przypisanie typów FS ✅.
-   Podstawowe modele danych i menedżer zadań w `core` ✅.
-   Prosty interfejs CLI do uruchamiania analiz (tymczasowy) ✅.

## Faza 2 – Wykrywanie szyfrowania (Tygodnie 6–9)

-   Moduł `crypto_detection` z heurystykami dla BitLocker, VeraCrypt, LUKS, FileVault (APFS) ✅ (konfigurowalne sygnatury).
-   Integracja z wynikami `fs_detection`, raportowanie statusu wolumenów ✅.
-   Rozszerzenie `drivers` o wsparcie EXT4 i APFS ✅.
-   Testy integracyjne na wzorcowych obrazach ✅.

## Faza 3 – Analiza metadanych (Tygodnie 10–13)

-   Implementacja rekurencyjnego skanera katalogów (`metadata`) ✅.
-   Zbieranie metadanych (nazwa, właściciel, daty, rozmiar, atrybuty, status szyfrowania) ✅.
-   Optymalizacja wydajności (praca wielowątkowa, kolejka zadań) ✅.
-   Walidacja danych i raportów JSON/CSV ✅.

## Faza 4 – GUI (Tygodnie 14–18)

-   Prototyp interfejsu w PySide6: ekran startowy, wybór źródła, selektor wolumenów, eksport raportów ✅.
-   Implementacja MVVM i integracja z warstwą `core` przez API usług ✅.
-   Obsługa przetwarzania w tle i postępu w UI ✅.
-   Lokalizacja (PL/EN) i testy użyteczności ✅.

## Faza 5 – Stabilizacja i rozszerzenia (Tygodnie 19–22)

-   Integracja z API No More Ransom (jeśli dostępne) lub przygotowanie abstrakcji.
-   Dodanie eksportu do dodatkowych formatów (np. PDF) – opcjonalnie.
-   Finalizacja dokumentacji użytkownika i dewelopera (częściowa – README/workflow aktualizowane na bieżąco).
-   Przygotowanie pakietu instalacyjnego (installer Windows, AppImage).

## Ciągłe działania

-   Testy regresyjne i rozszerzanie zestawu próbek.
-   Monitorowanie bezpieczeństwa zależności (Dependabot).
-   Analiza feedbacku i planowanie kolejnych wydań.
