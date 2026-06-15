
-- System Zarządzania Infrastrukturą VPN


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


-- ROLE

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'wbanek')   THEN CREATE ROLE wbanek WITH LOGIN PASSWORD 'haslo123';   END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dkubiela')  THEN CREATE ROLE dkubiela WITH LOGIN PASSWORD 'haslo123';  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ojasiak')   THEN CREATE ROLE ojasiak WITH LOGIN PASSWORD 'haslo123';   END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bbieda')    THEN CREATE ROLE bbieda WITH LOGIN PASSWORD 'haslo123';    END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vpn_readonly')  THEN CREATE ROLE vpn_readonly WITH LOGIN PASSWORD 'haslo123';  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vpn_operator')  THEN CREATE ROLE vpn_operator WITH LOGIN PASSWORD 'haslo123';  END IF;
END $$;


-- FUNKCJE PL/pgSQL


CREATE FUNCTION public.sprawdz_waznosc_klucza() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    wygasa  TIMESTAMP;
    aktywny BOOLEAN;
BEGIN
    SELECT data_wygasniecia, czy_aktywny
      INTO wygasa, aktywny
      FROM public.klucze_dostepu
     WHERE id_klucza = NEW.id_klucza;

    IF aktywny = FALSE THEN
        RAISE EXCEPTION 'Odmowa dostepu: Klucz zostal dezaktywowany.';
    ELSIF wygasa < CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'Odmowa dostepu: Klucz stracil waznosc (data wygasniecia minela).';
    END IF;

    RETURN NEW;
END;
$$;
ALTER FUNCTION public.sprawdz_waznosc_klucza() OWNER TO ojasiak;

CREATE FUNCTION public.blokuj_jednoczesne_sesje() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.logi_polaczen
         WHERE id_klucza = NEW.id_klucza
           AND czas_koniec IS NULL
    ) THEN
        RAISE EXCEPTION 'Odmowa dostepu: Wykryto juz aktywna sesje VPN dla tego klucza.';
    END IF;
    RETURN NEW;
END;
$$;
ALTER FUNCTION public.blokuj_jednoczesne_sesje() OWNER TO ojasiak;

CREATE FUNCTION public.rotacja_kluczy_uzytkownika() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    UPDATE public.klucze_dostepu
       SET czy_aktywny = FALSE
     WHERE id_uzytkownika = NEW.id_uzytkownika
       AND id_klucza      != NEW.id_klucza
       AND czy_aktywny    = TRUE;
    RETURN NEW;
END;
$$;
ALTER FUNCTION public.rotacja_kluczy_uzytkownika() OWNER TO ojasiak;


-- TABELE


SET default_tablespace = '';
SET default_table_access_method = heap;

CREATE TABLE public.uzytkownicy (
    id_uzytkownika   integer NOT NULL,
    login            character varying(50)  NOT NULL,
    email            character varying(100) NOT NULL,
    data_rejestracji timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE public.uzytkownicy OWNER TO wbanek;

CREATE SEQUENCE public.uzytkownicy_id_uzytkownika_seq
    AS integer START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
ALTER TABLE public.uzytkownicy_id_uzytkownika_seq OWNER TO wbanek;
ALTER SEQUENCE public.uzytkownicy_id_uzytkownika_seq OWNED BY public.uzytkownicy.id_uzytkownika;
ALTER TABLE ONLY public.uzytkownicy ALTER COLUMN id_uzytkownika
    SET DEFAULT nextval('public.uzytkownicy_id_uzytkownika_seq'::regclass);

CREATE TABLE public.klucze_dostepu (
    id_klucza        integer NOT NULL,
    id_uzytkownika   integer,
    hash_klucza      character varying(255) NOT NULL,
    data_wygasniecia timestamp without time zone NOT NULL,
    czy_aktywny      boolean DEFAULT true
);
ALTER TABLE public.klucze_dostepu OWNER TO wbanek;

CREATE SEQUENCE public.klucze_dostepu_id_klucza_seq
    AS integer START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
ALTER TABLE public.klucze_dostepu_id_klucza_seq OWNER TO wbanek;
ALTER SEQUENCE public.klucze_dostepu_id_klucza_seq OWNED BY public.klucze_dostepu.id_klucza;
ALTER TABLE ONLY public.klucze_dostepu ALTER COLUMN id_klucza
    SET DEFAULT nextval('public.klucze_dostepu_id_klucza_seq'::regclass);

CREATE TABLE public.serwery_vpn (
    id_serwera        integer NOT NULL,
    adres_ip          character varying(15)  NOT NULL,
    lokalizacja       character varying(100) NOT NULL,
    dostawca_hostingu character varying(100)
);
ALTER TABLE public.serwery_vpn OWNER TO wbanek;

CREATE SEQUENCE public.serwery_vpn_id_serwera_seq
    AS integer START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
ALTER TABLE public.serwery_vpn_id_serwera_seq OWNER TO wbanek;
ALTER SEQUENCE public.serwery_vpn_id_serwera_seq OWNED BY public.serwery_vpn.id_serwera;
ALTER TABLE ONLY public.serwery_vpn ALTER COLUMN id_serwera
    SET DEFAULT nextval('public.serwery_vpn_id_serwera_seq'::regclass);

CREATE TABLE public.tunele_vpn (
    id_tunelu  integer NOT NULL,
    id_serwera integer,
    protokol   character varying(20) NOT NULL,
    port       integer NOT NULL,
    CONSTRAINT tunele_vpn_protokol_check
        CHECK (protokol IN ('OpenVPN','WireGuard','IPsec'))
);
ALTER TABLE public.tunele_vpn OWNER TO wbanek;

CREATE SEQUENCE public.tunele_vpn_id_tunelu_seq
    AS integer START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
ALTER TABLE public.tunele_vpn_id_tunelu_seq OWNER TO wbanek;
ALTER SEQUENCE public.tunele_vpn_id_tunelu_seq OWNED BY public.tunele_vpn.id_tunelu;
ALTER TABLE ONLY public.tunele_vpn ALTER COLUMN id_tunelu
    SET DEFAULT nextval('public.tunele_vpn_id_tunelu_seq'::regclass);

CREATE TABLE public.logi_polaczen (
    id_logu     integer NOT NULL,
    id_klucza   integer,
    id_tunelu   integer,
    czas_start  timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    czas_koniec timestamp without time zone
);
ALTER TABLE public.logi_polaczen OWNER TO wbanek;

CREATE SEQUENCE public.logi_polaczen_id_logu_seq
    AS integer START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
ALTER TABLE public.logi_polaczen_id_logu_seq OWNER TO wbanek;
ALTER SEQUENCE public.logi_polaczen_id_logu_seq OWNED BY public.logi_polaczen.id_logu;
ALTER TABLE ONLY public.logi_polaczen ALTER COLUMN id_logu
    SET DEFAULT nextval('public.logi_polaczen_id_logu_seq'::regclass);

CREATE TABLE public.pomiary_parametrow (
    id_pomiaru         integer NOT NULL,
    id_logu            integer,
    opoznienie_ms      integer NOT NULL,
    przepustowosc_mbps numeric(8,2) NOT NULL,
    czas_pomiaru       timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pomiary_parametrow_opoznienie_ms_check
        CHECK (opoznienie_ms >= 0),
    CONSTRAINT pomiary_parametrow_przepustowosc_mbps_check
        CHECK (przepustowosc_mbps >= 0)
);
ALTER TABLE public.pomiary_parametrow OWNER TO wbanek;

CREATE SEQUENCE public.pomiary_parametrow_id_pomiaru_seq
    AS integer START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
ALTER TABLE public.pomiary_parametrow_id_pomiaru_seq OWNER TO wbanek;
ALTER SEQUENCE public.pomiary_parametrow_id_pomiaru_seq OWNED BY public.pomiary_parametrow.id_pomiaru;
ALTER TABLE ONLY public.pomiary_parametrow ALTER COLUMN id_pomiaru
    SET DEFAULT nextval('public.pomiary_parametrow_id_pomiaru_seq'::regclass);


-- KLUCZE GŁÓWNE I UNIKALNE

ALTER TABLE ONLY public.uzytkownicy
    ADD CONSTRAINT uzytkownicy_pkey       PRIMARY KEY (id_uzytkownika),
    ADD CONSTRAINT uzytkownicy_login_key  UNIQUE (login),
    ADD CONSTRAINT uzytkownicy_email_key  UNIQUE (email);

ALTER TABLE ONLY public.klucze_dostepu
    ADD CONSTRAINT klucze_dostepu_pkey             PRIMARY KEY (id_klucza),
    ADD CONSTRAINT klucze_dostepu_hash_klucza_key  UNIQUE (hash_klucza);

ALTER TABLE ONLY public.serwery_vpn
    ADD CONSTRAINT serwery_vpn_pkey        PRIMARY KEY (id_serwera),
    ADD CONSTRAINT serwery_vpn_adres_ip_key UNIQUE (adres_ip);

ALTER TABLE ONLY public.tunele_vpn
    ADD CONSTRAINT tunele_vpn_pkey PRIMARY KEY (id_tunelu);

ALTER TABLE ONLY public.logi_polaczen
    ADD CONSTRAINT logi_polaczen_pkey PRIMARY KEY (id_logu);

ALTER TABLE ONLY public.pomiary_parametrow
    ADD CONSTRAINT pomiary_parametrow_pkey PRIMARY KEY (id_pomiaru);


-- KLUCZE OBCE

ALTER TABLE ONLY public.klucze_dostepu
    ADD CONSTRAINT klucze_dostepu_id_uzytkownika_fkey
        FOREIGN KEY (id_uzytkownika)
        REFERENCES public.uzytkownicy(id_uzytkownika) ON DELETE CASCADE;

ALTER TABLE ONLY public.tunele_vpn
    ADD CONSTRAINT tunele_vpn_id_serwera_fkey
        FOREIGN KEY (id_serwera)
        REFERENCES public.serwery_vpn(id_serwera) ON DELETE CASCADE;

ALTER TABLE ONLY public.logi_polaczen
    ADD CONSTRAINT logi_polaczen_id_klucza_fkey
        FOREIGN KEY (id_klucza) REFERENCES public.klucze_dostepu(id_klucza),
    ADD CONSTRAINT logi_polaczen_id_tunelu_fkey
        FOREIGN KEY (id_tunelu) REFERENCES public.tunele_vpn(id_tunelu);

ALTER TABLE ONLY public.pomiary_parametrow
    ADD CONSTRAINT pomiary_parametrow_id_logu_fkey
        FOREIGN KEY (id_logu)
        REFERENCES public.logi_polaczen(id_logu) ON DELETE CASCADE;


-- INDEKSY

CREATE INDEX idx_klucze_uzytkownik ON public.klucze_dostepu(id_uzytkownika);
CREATE INDEX idx_klucze_aktywny    ON public.klucze_dostepu(czy_aktywny, data_wygasniecia);
CREATE INDEX idx_logi_klucz        ON public.logi_polaczen(id_klucza);
CREATE INDEX idx_logi_tunel        ON public.logi_polaczen(id_tunelu);
CREATE INDEX idx_logi_aktywne      ON public.logi_polaczen(czas_koniec) WHERE czas_koniec IS NULL;
CREATE INDEX idx_pomiary_logu      ON public.pomiary_parametrow(id_logu);


-- TRIGGERY

CREATE TRIGGER trg_sprawdz_klucz
    BEFORE INSERT ON public.logi_polaczen
    FOR EACH ROW EXECUTE FUNCTION public.sprawdz_waznosc_klucza();

CREATE TRIGGER trg_blokuj_wielokrotne_sesje
    BEFORE INSERT ON public.logi_polaczen
    FOR EACH ROW EXECUTE FUNCTION public.blokuj_jednoczesne_sesje();

CREATE TRIGGER trg_rotacja_kluczy
    AFTER INSERT ON public.klucze_dostepu
    FOR EACH ROW EXECUTE FUNCTION public.rotacja_kluczy_uzytkownika();

-- WIDOKI

CREATE VIEW public.v_aktywne_polaczenia AS
    SELECT u.login, s.adres_ip, t.protokol, l.czas_start
      FROM public.logi_polaczen l
      JOIN public.klucze_dostepu k ON l.id_klucza      = k.id_klucza
      JOIN public.uzytkownicy    u ON k.id_uzytkownika = u.id_uzytkownika
      JOIN public.tunele_vpn     t ON l.id_tunelu      = t.id_tunelu
      JOIN public.serwery_vpn    s ON t.id_serwera     = s.id_serwera
     WHERE l.czas_koniec IS NULL;
ALTER TABLE public.v_aktywne_polaczenia OWNER TO dkubiela;

CREATE VIEW public.v_audyt_bezpieczenstwa AS
    SELECT u.login, u.email,
           k.czy_aktywny AS status_klucza,
           k.data_wygasniecia,
           date_part('day', (k.data_wygasniecia::timestamp with time zone - CURRENT_TIMESTAMP))
               AS dni_do_wygasniecia
      FROM public.uzytkownicy    u
      JOIN public.klucze_dostepu k ON u.id_uzytkownika = k.id_uzytkownika
     WHERE k.czy_aktywny = false
        OR k.data_wygasniecia < (CURRENT_TIMESTAMP + INTERVAL '14 days')
     ORDER BY k.data_wygasniecia;
ALTER TABLE public.v_audyt_bezpieczenstwa OWNER TO dkubiela;

CREATE VIEW public.v_wydajnosc_infrastruktury AS
    SELECT s.lokalizacja, t.protokol,
           count(DISTINCT l.id_logu)                   AS suma_sesji,
           COALESCE(round(avg(p.opoznienie_ms), 0), 0) AS srednie_opoznienie_ms,
           COALESCE(max(p.przepustowosc_mbps), 0)      AS szczytowa_przepustowosc_mbps
      FROM public.serwery_vpn s
      JOIN public.tunele_vpn          t ON s.id_serwera = t.id_serwera
      LEFT JOIN public.logi_polaczen  l ON t.id_tunelu  = l.id_tunelu
      LEFT JOIN public.pomiary_parametrow p ON l.id_logu = p.id_logu
     GROUP BY s.lokalizacja, t.protokol
     ORDER BY srednie_opoznienie_ms DESC;
ALTER TABLE public.v_wydajnosc_infrastruktury OWNER TO dkubiela;


SET session_replication_role = replica;  -- wyłącza triggery tymczasowo

INSERT INTO public.uzytkownicy (id_uzytkownika, login, email, data_rejestracji) VALUES
(1, 'jan_sieciowiec', 'jan@vpn-test.pl',   '2026-06-08 19:03:55.574163'),
(2, 'admin_jan',      'jan@vpn.pl',         '2026-06-08 19:04:46.890470'),
(3, 'testowy_adam',   'adam@vpn.pl',        '2026-06-08 19:04:46.890470'),
(4, 'haker_zly',      'zly@vpn.pl',         '2026-06-08 19:04:46.890470'),
(5, 'devops_linux',   'linux_admin@vpn.pl', '2026-06-08 19:22:35.183085'),
(6, 'mac_user',       'osx_team@vpn.pl',    '2026-06-08 19:22:35.183085'),
(7, 'sdn_tester',     'mininet_lab@vpn.pl', '2026-06-08 19:22:35.183085'),
(8, 'cloud_eng',      'k8s_dev@vpn.pl',     '2026-06-08 19:22:35.183085'),
(9, 'stazysta_it',    'staz@vpn.pl',        '2026-06-08 19:22:35.183085');

INSERT INTO public.klucze_dostepu (id_klucza, id_uzytkownika, hash_klucza, data_wygasniecia, czy_aktywny) VALUES
(1, 1, 'xyz_tajny_hash_123',   '2027-06-08 19:03:55.574163', true),
(2, 1, 'hash_wazny_123',       '2026-07-08 19:04:46.891080', true),
(3, 2, 'hash_stary_456',       '2026-06-07 19:04:46.891753', true),   -- celowo wygasly
(4, 3, 'hash_zablokowany_789', '2026-07-08 19:04:46.892350', false),  -- celowo dezaktywowany
(5, 4, 'hash_linux_001',       '2026-12-05 19:23:56.085215', true),
(6, 5, 'hash_mac_002',         '2026-09-06 19:23:56.085215', true),
(7, 6, 'hash_sdn_003',         '2026-06-15 19:23:56.085215', true),
(8, 7, 'hash_cloud_004',       '2026-06-03 19:23:56.085215', true),
(9, 8, 'hash_stazysta_005',    '2026-06-22 19:23:56.085215', false);

INSERT INTO public.serwery_vpn (id_serwera, adres_ip, lokalizacja, dostawca_hostingu) VALUES
(1, '192.168.1.100', 'Warszawa, Polska',    'OVH'),
(2, '10.0.5.50',     'Frankfurt, Niemcy',   'AWS'),
(3, '10.20.30.40',   'Krakow, Polska',      'Comarch Cloud'),
(4, '192.168.50.1',  'Amsterdam, Holandia', 'DigitalOcean'),
(5, '172.16.0.5',    'Nowy Jork, USA',      'AWS');

INSERT INTO public.tunele_vpn (id_tunelu, id_serwera, protokol, port) VALUES
(1, 1, 'OpenVPN',   1194),
(2, 2, 'WireGuard', 51820),
(3, 3, 'IPsec',     500),
(4, 3, 'WireGuard', 51821),
(5, 4, 'WireGuard', 51820),
(6, 5, 'OpenVPN',   1194);

INSERT INTO public.logi_polaczen (id_logu, id_klucza, id_tunelu, czas_start, czas_koniec) VALUES
( 2, 2, 2, '2026-06-08 19:05:48.565625', NULL),
( 3, 1, 1, '2026-06-08 19:06:40.578675', NULL),
( 6, 5, 3, '2026-06-08 17:31:40.788220', '2026-06-08 18:31:40.788220'),
( 7, 5, 5, '2026-06-08 19:01:40.788220', NULL),
( 8, 6, 4, '2026-06-08 14:31:40.788220', '2026-06-08 17:31:40.788220'),
( 9, 7, 6, '2026-06-08 19:16:40.788220', NULL),
(10, 1, 4, '2026-06-07 19:31:40.788220', '2026-06-07 20:31:40.788220');

INSERT INTO public.pomiary_parametrow (id_pomiaru, id_logu, opoznienie_ms, przepustowosc_mbps, czas_pomiaru) VALUES
(17,  6,  12, 850.00, '2026-06-08 19:33:01.316894'),
(18,  6,  14, 840.50, '2026-06-08 19:33:01.316894'),
(19,  7,  45, 320.00, '2026-06-08 19:33:01.316894'),
(20,  8,  15, 900.20, '2026-06-08 19:33:01.316894'),
(21,  8,  16, 890.00, '2026-06-08 19:33:01.316894'),
(22,  9, 120,  45.50, '2026-06-08 19:33:01.316894'),
(23,  9, 125,  42.00, '2026-06-08 19:33:01.316894'),
(24, 10,  18, 750.00, '2026-06-08 19:33:01.316894');

SET session_replication_role = DEFAULT;  -- włącza triggery z powrotem


-- SEKWENCJE – ustawienie po wstawieniu danych

SELECT pg_catalog.setval('public.klucze_dostepu_id_klucza_seq',      9, true);
SELECT pg_catalog.setval('public.logi_polaczen_id_logu_seq',         10, true);
SELECT pg_catalog.setval('public.pomiary_parametrow_id_pomiaru_seq', 24, true);
SELECT pg_catalog.setval('public.serwery_vpn_id_serwera_seq',         5, true);
SELECT pg_catalog.setval('public.tunele_vpn_id_tunelu_seq',           6, true);
SELECT pg_catalog.setval('public.uzytkownicy_id_uzytkownika_seq',     9, true);


-- UPRAWNIENIA ZESPOŁU


-- dkubiela 
GRANT ALL ON TABLE public.uzytkownicy        TO dkubiela;
GRANT ALL ON TABLE public.klucze_dostepu     TO dkubiela;
GRANT ALL ON TABLE public.serwery_vpn        TO dkubiela;
GRANT ALL ON TABLE public.tunele_vpn         TO dkubiela;
GRANT ALL ON TABLE public.logi_polaczen      TO dkubiela;
GRANT ALL ON TABLE public.pomiary_parametrow TO dkubiela;
GRANT ALL ON TABLE public.v_aktywne_polaczenia       TO wbanek;
GRANT ALL ON TABLE public.v_audyt_bezpieczenstwa     TO wbanek;
GRANT ALL ON TABLE public.v_wydajnosc_infrastruktury TO wbanek;

-- ojasiak 
GRANT SELECT, INSERT, UPDATE, TRIGGER ON TABLE public.uzytkownicy        TO ojasiak;
GRANT SELECT, INSERT, UPDATE, TRIGGER ON TABLE public.klucze_dostepu     TO ojasiak;
GRANT SELECT, INSERT, UPDATE, TRIGGER ON TABLE public.serwery_vpn        TO ojasiak;
GRANT SELECT, INSERT, UPDATE, TRIGGER ON TABLE public.tunele_vpn         TO ojasiak;
GRANT SELECT, INSERT, UPDATE, TRIGGER ON TABLE public.logi_polaczen      TO ojasiak;
GRANT SELECT, INSERT, UPDATE, TRIGGER ON TABLE public.pomiary_parametrow TO ojasiak;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO ojasiak;

-- bbieda 
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.uzytkownicy        TO bbieda;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.klucze_dostepu     TO bbieda;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.serwery_vpn        TO bbieda;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.tunele_vpn         TO bbieda;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.logi_polaczen      TO bbieda;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.pomiary_parametrow TO bbieda;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO bbieda;

-- Role produkcyjne (zasada najmniejszych uprawnień)
GRANT SELECT ON ALL TABLES    IN SCHEMA public TO vpn_readonly;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO vpn_readonly;

GRANT SELECT, INSERT, UPDATE ON TABLE public.logi_polaczen      TO vpn_operator;
GRANT SELECT, INSERT, UPDATE ON TABLE public.pomiary_parametrow TO vpn_operator;
GRANT SELECT                 ON TABLE public.klucze_dostepu     TO vpn_operator;
GRANT SELECT                 ON TABLE public.tunele_vpn         TO vpn_operator;

GRANT USAGE, SELECT ON SEQUENCE public.logi_polaczen_id_logu_seq       TO vpn_operator;
GRANT USAGE, SELECT ON SEQUENCE public.pomiary_parametrow_id_pomiaru_seq TO vpn_operator;

