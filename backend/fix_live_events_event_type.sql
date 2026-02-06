-- ============================================================
-- FIX: Aggiunge colonna event_type mancante a live_events
-- Data: 2025-01-21
-- Problema: Model SQLAlchemy ha event_type ma tabella DB no
-- ============================================================

-- 1. Crea il tipo ENUM se non esiste
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'liveeventtype') THEN
        CREATE TYPE liveeventtype AS ENUM (
            'live_class',
            'workshop', 
            'seminar',
            'competition',
            'qna',
            'fundraising'
        );
    END IF;
END $$;

-- 2. Aggiungi la colonna se non esiste
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'live_events' AND column_name = 'event_type'
    ) THEN
        ALTER TABLE live_events ADD COLUMN event_type liveeventtype;
        
        -- 3. Imposta valore default per righe esistenti
        UPDATE live_events SET event_type = 'live_class' WHERE event_type IS NULL;
        
        -- 4. Rendi NOT NULL dopo aver popolato
        ALTER TABLE live_events ALTER COLUMN event_type SET NOT NULL;
        
        -- 5. Crea indice per performance
        CREATE INDEX IF NOT EXISTS idx_live_event_type ON live_events(event_type, scheduled_start);
        
        RAISE NOTICE 'Colonna event_type aggiunta con successo!';
    ELSE
        RAISE NOTICE 'Colonna event_type esiste già.';
    END IF;
END $$;

-- Verifica
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'live_events' AND column_name = 'event_type';
