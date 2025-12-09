# CryptoAnalyzer – Dokumentacja

CryptoAnalyzer to narzędzie do analizy dysków i obrazów dysków pod kątem szyfrowania oraz struktury danych. Projekt rozwijamy w języku Python, z graficznym interfejsem użytkownika, kładąc nacisk na modularną architekturę i możliwość dalszej rozbudowy (m.in. integrację z API No More Ransom).

## Zakres systemów plików

Pierwsza wersja aplikacji obsługuje następujące systemy plików:

-   NTFS
-   EXT4
-   FAT32
-   APFS

## Główne cele projektu

-   Wykrywanie rodzaju źródła (fizyczny dysk lub obraz dysku) i identyfikacja dostępnych wolumenów.
-   Automatyczne rozpoznawanie systemu plików oraz heurystyczne wykrywanie szyfrowania i jego wersji.
-   Analiza struktury katalogów i plików wraz z metadanymi (nazwa, ścieżka, właściciel, rozmiar, daty utworzenia i modyfikacji, dodatkowe atrybuty).
-   Prezentacja wyników w formie hierarchicznego widoku (wolumen → katalog → plik) z możliwością interaktywnej eksploracji.
-   Eksport raportów do formatów CSV i JSON.

## Docelowe środowisko uruchomieniowe

-   Python 3.11+
-   Systemy operacyjne: Windows (preferowana), Linux, macOS (w zależności od wsparcia bibliotek niskopoziomowych).

## Struktura dokumentacji

-   `architecture.md` – architektura systemu, podział na moduły, zależności, konwencje kodu.
-   `workflow.md` – szczegółowy opis przepływu użytkownika i scenariuszy użycia.
-   `roadmap.md` – plan rozwoju projektu i kamienie milowe.

W miarę rozwoju projektu dokumentacja będzie rozbudowywana o dodatkowe rozdziały (np. instrukcje wdrożenia, poradniki developerskie, przewodnik po API).

## Konfiguracja sygnatur szyfrowania

Tabela sygnatur wykorzystywana przez moduł `crypto_detection` znajduje się w pliku `src/crypto_analyzer/data/encryption_signatures.json`. Dodanie nowego algorytmu sprowadza się do dopisania kolejnego wpisu (wraz z matcherami i sposobem ekstrakcji wersji), bez konieczności modyfikacji kodu detektora.
