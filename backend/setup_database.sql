-- ========================================
-- Setup Database e Utente per Media Center Arti Marziali
-- ========================================

-- Crea utente (se non esiste)
DO
$$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'martial_user') THEN
      CREATE USER martial_user WITH PASSWORD 'martial_pass';
   END IF;
END
$$;

-- Crea database (usa impostazioni di default del server)
CREATE DATABASE martial_arts_db
    WITH
    OWNER = martial_user
    ENCODING = 'UTF8'
    TEMPLATE = template0;

-- Concedi tutti i privilegi
GRANT ALL PRIVILEGES ON DATABASE martial_arts_db TO martial_user;

-- Connettiti al nuovo database e concedi privilegi sugli schemi
\c martial_arts_db

GRANT ALL ON SCHEMA public TO martial_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO martial_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO martial_user;

-- Imposta i privilegi di default per tabelle future
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO martial_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO martial_user;

-- Verifica
\echo '================================'
\echo 'Setup completato!'
\echo 'Database: martial_arts_db'
\echo 'Utente: martial_user'
\echo 'Password: martial_pass'
\echo 'Porta: 5432'
\echo '================================'
\echo ''
\echo 'Lista database:'
\l
\echo ''
\echo 'Lista utenti:'
\du
