# System Zarządzania Infrastrukturą VPN - Baza Danych

## Opis projektu
Relacyjna baza danych (PostgreSQL) zaprojektowana do zarządzania infrastrukturą sieci VPN. System obsługuje ewidencję użytkowników, rotację kluczy dostępu, logowanie sesji tunelowych oraz gromadzenie danych telemetrycznych (opóźnienia i przepustowość). Środowisko jest w pełni skonteneryzowane i implementuje model bezpieczeństwa oparty na rolach (RBAC) oraz procedurach wyzwalanych (triggery).

## Wymagania
* Docker
* Docker Compose

## Zawartość repozytorium
* `docker-compose.yml` - konfiguracja środowiska uruchomieniowego.
* `projekt_vpn.sql` - główny skrypt inicjalizujący schemat bazy, dane testowe oraz uprawnienia.
* `dokumentacja_techniczna.pdf` - szczegółowy opis architektury i normalizacji.

## Uruchomienie środowiska

1. Pobranie obrazu i uruchomienie kontenera w tle:
```bash
    docker compose up -d
```

2. Załadowanie struktury bazy danych, ról i danych testowych:
```bash
    cat projekt_vpn.sql | docker exec -i serwer_vpn_agh psql -U postgres -d VPN_db
```

## Logowanie do bazy i testowanie

Aby wejść do interaktywnej konsoli bazy danych jako superużytkownik, wykonaj:
```bash
    docker exec -it serwer_vpn_agh psql -U postgres -d VPN_db
```

Wewnątrz konsoli można testować uprawnienia logując się na dedykowane role (np. analityk, audytor, operator L1). Służy do tego polecenie:
```sql
    \c VPN_db nazwa_uzytkownika
```

**Dostępne konta testowe:** `wbanek`, `dkubiela`, `ojasiak`, `bbieda`, `vpn_operator`, `vpn_readonly`.  
**Hasło dla wszystkich ról:** `haslo123`

## Czyszczenie środowiska

Aby wyłączyć bazę i usunąć tymczasowe woluminy (przywrócenie czystego stanu przed kolejnym startem):
```bash
    docker compose down -v
```
