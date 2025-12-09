# Przepływ użytkownika i scenariusze

## Główny scenariusz analizy

1. **Uruchomienie aplikacji** – ekran powitalny z krótkim opisem i dwoma opcjami źródła danych.
2. **Wybór źródła** – użytkownik wybiera:
    - fizyczny dysk podłączony do systemu, lub
    - obraz dysku (RAW, E01/EWF, VHD/VHDX).
3. **Selektor ścieżki** – w zależności od wyboru:
    - lista dostępnych dysków (z nazwą, rozmiarem, identyfikatorem);
    - okno dialogowe wyboru pliku obrazu.
4. **Identyfikacja systemów plików i wolumenów** – aplikacja analizuje nagłówki, wykrywa partycje, typy systemów plików (NTFS, EXT4, FAT32, APFS) oraz status szyfrowania na poziomie wolumenu.
5. **Wybór wolumenów do analizy** – ekran z checklistą wolumenów. Użytkownik decyduje, które wolumeny uwzględnić (pojedyncze, wiele lub wszystkie).
6. **Analiza szyfrowania** – moduł `crypto_detection` identyfikuje algorytm, wariant/wersję (np. BitLocker XTS-AES 128) oraz dostępność metadanych umożliwiających deszyfrację (jeśli to możliwe).
7. **Analiza struktury katalogów** – moduł `metadata` buduje drzewo katalogów i plików, zbierając metadane: nazwa, pełna ścieżka, rozmiar, właściciel, daty utworzenia/modyfikacji/dostępu, atrybuty specjalne. Dla szyfrowanych elementów odnotowywany jest status (np. „zaszyfrowany w całości”, „poszczególne pliki”).
8. **Prezentacja wyników** – widok raportu z dwoma panelami:
    - podsumowanie globalne (system plików, wykryte szyfrowanie, liczba plików/katalogów, czas analizy);
    - panel drzewa z możliwością rozwijania wolumenów → katalogów → plików (podobnie do eksploratora plików).
      Dla każdego elementu dostępny jest panel szczegółów (pełne metadane, identyfikatory hash – opcjonalnie).
9. **Eksport raportu** – przyciski „Eksportuj do CSV” i „Eksportuj do JSON”. Raport zawiera:
    - dane globalne (źródło, systemy plików, wolumeny, szyfrowanie);
    - szczegółową listę elementów z metadanymi;
    - strukturę hierarchiczną zachowaną poprzez odpowiednie kolumny (np. ścieżka, identyfikator rodzica).
10. **Zakończenie** – możliwość uruchomienia kolejnej analizy lub zakończenia pracy.

## Scenariusze dodatkowe

-   **Analiza wybranych folderów** – po zakończeniu skanowania użytkownik może filtrować wyniki (np. po rozszerzeniu, dacie, statusie szyfrowania).
-   **Integracja z API No More Ransom (przyszłość)** – w widoku wyników pojawia się przycisk „Sprawdź możliwe narzędzia deszyfrujące”. System wysyła metadane do zewnętrznego API i prezentuje dostępne rozwiązania.
-   **Tryb tylko-metadane** – opcja uruchomienia analizy bez heurystyk szyfrowania (szybsza, do celów inwentaryzacji).

## Wymagania UX/UI

-   Responsywne komponenty Qt zapewniające płynność na ekranach 13"+. Minimalna rozdzielczość 1280×720.
-   Pasek postępu i log strumieniowy podczas analiz, z możliwością rozwinięcia szczegółów (np. identyfikowane pliki, wykryte sygnatury).
-   Obsługa języków PL/EN (przyszłe rozszerzenie), z wydzielonym modułem i18n w `shared`.
-   Bezpieczne operowanie na źródłach: wszystkie operacje w trybie tylko-do-odczytu; ostrzeżenia przed wykonywaniem modyfikacji.
