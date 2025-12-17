# Przepływ użytkownika i scenariusze

## Główny scenariusz analizy

1. **Uruchomienie aplikacji** – ekran powitalny z opisem i przyciskami wyboru źródła.
2. **Wybór źródła** – użytkownik może:
    - wybrać dysk fizyczny z listy dostarczonej przez `TskPhysicalDiskDriver` (informacja o dostępności i uprawnieniach);
    - wskazać plik obrazu (RAW/IMG/E01/VHD(VHDX)) poprzez dialog systemowy.
3. **Identyfikacja wolumenów** – aplikacja inicjuje `AnalysisManager`, enumeruje źródło, a TSK wykrywa partycje oraz typy systemów plików.
4. **Selektor wolumenów** – użytkownik zobaczy dialog z listą wolumenów (rozmiary, identyfikatory) i może wybrać jedną lub wiele pozycji.
5. **Analiza szyfrowania** – `SignatureBasedDetector` uruchamia heurystyki (BitLocker, VeraCrypt, LUKS, FileVault, itp.) dla wybranych wolumenów.
6. **Skan metadanych** – aktualna wersja GUI wykonuje szybkie skanowanie (głębokość 0) w celu zachowania responsywności; pełne drzewo katalogów jest przewidziane w roadmapie.
7. **Podsumowanie** – użytkownik otrzymuje okno z opisem wyników (system plików, status szyfrowania, liczba wolumenów) oraz informację na pasku statusu.
8. **Eksport raportu** – przyciski w głównym oknie generują raport w formacie JSON/CSV przy użyciu `DefaultReportExporter`.
9. **Dalsze kroki** – planowane jest rozwinięcie widoku raportu o szczegółowe drzewo, rozbudowany pasek postępu i integrację z API No More Ransom.

## Scenariusze dodatkowe

-   **Analiza wybranych folderów** – po zakończeniu skanowania użytkownik może filtrować wyniki (np. po rozszerzeniu, dacie, statusie szyfrowania).
-   **Integracja z API No More Ransom (przyszłość)** – w widoku wyników pojawia się przycisk „Sprawdź możliwe narzędzia deszyfrujące”. System wysyła metadane do zewnętrznego API i prezentuje dostępne rozwiązania.
-   **Tryb tylko-metadane** – opcja uruchomienia analizy bez heurystyk szyfrowania (szybsza, do celów inwentaryzacji).

## Wymagania UX/UI

-   Responsywne komponenty Qt zapewniające płynność na ekranach 13"+. Minimalna rozdzielczość 1280×720.
-   Pasek postępu i log strumieniowy podczas analiz, z możliwością rozwinięcia szczegółów (np. identyfikowane pliki, wykryte sygnatury).
-   Obsługa języków PL/EN (przyszłe rozszerzenie), z wydzielonym modułem i18n w `shared`.
-   Bezpieczne operowanie na źródłach: wszystkie operacje w trybie tylko-do-odczytu; ostrzeżenia przed wykonywaniem modyfikacji.
