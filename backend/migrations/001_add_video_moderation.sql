-- ========================================
-- Migration: Video Moderation System
-- Version: 001
-- Date: 2025-11-20
-- Description: Aggiunge sistema di moderazione video con trust levels per maestri
-- ========================================

-- ========================================
-- STEP 1: Modifica tabella MAESTROS
-- Aggiungi trust levels e auto-publish
-- ========================================

-- Permesso auto-pubblicazione (default: false)
ALTER TABLE maestros
ADD COLUMN auto_publish_enabled BOOLEAN NOT NULL DEFAULT false;

-- Livello di verifica/fiducia (0-2)
ALTER TABLE maestros
ADD COLUMN verification_level INTEGER NOT NULL DEFAULT 0;

-- Commenti sui livelli:
-- 0 = Base (sempre moderazione richiesta)
-- 1 = Verificato (moderazione occasionale/random spot-check)
-- 2 = Trusted (auto-publish sempre attivo)

COMMENT ON COLUMN maestros.auto_publish_enabled IS 'Se true, video pubblicati automaticamente dopo encoding';
COMMENT ON COLUMN maestros.verification_level IS 'Livello di fiducia: 0=Base, 1=Verificato, 2=Trusted';

-- ========================================
-- STEP 2: Nuova tabella VIDEO_MODERATION
-- Storico completo delle moderazioni
-- ========================================

CREATE TABLE video_moderation (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,

    -- Chi ha moderato (NULL per auto-approval)
    moderator_user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Azione effettuata
    action VARCHAR(20) NOT NULL,
    -- Valori possibili: 'APPROVED', 'REJECTED', 'NEEDS_CHANGES', 'AUTO_APPROVED'

    -- Transizione di stato
    previous_status VARCHAR(20) NOT NULL,
    new_status VARCHAR(20) NOT NULL,

    -- Note e motivazioni
    moderation_notes TEXT,
    rejection_reason TEXT,

    -- Array di modifiche richieste (se action = 'NEEDS_CHANGES')
    required_changes TEXT[],

    -- Validazione metadata (JSON con score e issues)
    metadata_validation JSONB,
    -- Esempio: {"valid": true, "score": 95, "issues": [], "warnings": ["No tags"]}

    -- Timestamp
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indici per performance
CREATE INDEX idx_video_moderation_video
ON video_moderation(video_id, created_at DESC);

CREATE INDEX idx_video_moderation_moderator
ON video_moderation(moderator_user_id);

CREATE INDEX idx_video_moderation_action
ON video_moderation(action, created_at DESC);

-- Commenti
COMMENT ON TABLE video_moderation IS 'Storico completo moderazione video';
COMMENT ON COLUMN video_moderation.action IS 'APPROVED, REJECTED, NEEDS_CHANGES, AUTO_APPROVED';
COMMENT ON COLUMN video_moderation.metadata_validation IS 'JSON con risultati validazione automatica';

-- ========================================
-- STEP 3: Modifica tabella VIDEOS
-- Aggiungi campi approvazione e rifiuto
-- ========================================

-- Chi ha approvato il video (staff/admin)
ALTER TABLE videos
ADD COLUMN approved_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- Quando è stato approvato
ALTER TABLE videos
ADD COLUMN approved_at TIMESTAMP;

-- Motivo rifiuto (se status = ARCHIVED)
ALTER TABLE videos
ADD COLUMN rejection_reason TEXT;

-- Note per modifiche richieste (se NEEDS_CHANGES)
ALTER TABLE videos
ADD COLUMN needs_changes_notes TEXT;

COMMENT ON COLUMN videos.approved_by IS 'User ID dello staff che ha approvato il video';
COMMENT ON COLUMN videos.approved_at IS 'Data e ora approvazione';
COMMENT ON COLUMN videos.rejection_reason IS 'Motivo rifiuto se status=ARCHIVED';
COMMENT ON COLUMN videos.needs_changes_notes IS 'Note per maestro su modifiche richieste';

-- ========================================
-- STEP 4: Dati di esempio (OPZIONALE - solo per testing)
-- ========================================

-- Esempio: Rendi il Maestro Shifu "trusted"
-- (Commentato - eseguire manualmente se necessario)

/*
UPDATE maestros
SET auto_publish_enabled = true,
    verification_level = 2
WHERE user_id = (SELECT id FROM users WHERE username = 'maestro_shifu');
*/

-- ========================================
-- ROLLBACK SCRIPT (da usare in caso di problemi)
-- ========================================

/*
-- ATTENZIONE: Questo elimina TUTTI i dati delle modifiche!
-- Eseguire solo in caso di rollback necessario

-- Step 1: Rimuovi campi da videos
ALTER TABLE videos DROP COLUMN IF EXISTS approved_by;
ALTER TABLE videos DROP COLUMN IF EXISTS approved_at;
ALTER TABLE videos DROP COLUMN IF EXISTS rejection_reason;
ALTER TABLE videos DROP COLUMN IF EXISTS needs_changes_notes;

-- Step 2: Elimina tabella video_moderation
DROP TABLE IF EXISTS video_moderation;

-- Step 3: Rimuovi campi da maestros
ALTER TABLE maestros DROP COLUMN IF EXISTS auto_publish_enabled;
ALTER TABLE maestros DROP COLUMN IF EXISTS verification_level;
*/

-- ========================================
-- VERIFICA POST-MIGRATION
-- ========================================

-- Verifica colonne maestros
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_name = 'maestros'
  AND column_name IN ('auto_publish_enabled', 'verification_level')
ORDER BY column_name;

-- Verifica tabella video_moderation creata
SELECT table_name
FROM information_schema.tables
WHERE table_name = 'video_moderation';

-- Verifica colonne videos
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_name = 'videos'
  AND column_name IN ('approved_by', 'approved_at', 'rejection_reason', 'needs_changes_notes')
ORDER BY column_name;

-- ========================================
-- FINE MIGRATION
-- ========================================
