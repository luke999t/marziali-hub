-- Migration 008: Add avatars table for 3D avatar system
-- AI_MODULE: Avatar Migration
-- AI_DESCRIPTION: Crea tabella avatars per gestione modelli 3D con bone mapping MediaPipe
-- Date: 2026-01-28

-- Tabella avatars
CREATE TABLE IF NOT EXISTS avatars (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    style VARCHAR(50) NOT NULL DEFAULT 'generic',

    -- File info
    model_url VARCHAR(500) NOT NULL,
    thumbnail_url VARCHAR(500),
    file_size_bytes INTEGER,

    -- Rig info
    rig_type VARCHAR(50) NOT NULL DEFAULT 'readyplayerme',
    bone_count INTEGER,
    has_hand_bones BOOLEAN NOT NULL DEFAULT TRUE,

    -- Visibility & status
    is_public BOOLEAN NOT NULL DEFAULT TRUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Ownership
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- License
    license_type VARCHAR(50) NOT NULL DEFAULT 'cc_by',
    attribution TEXT,

    -- Timestamps
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes per query frequenti
CREATE INDEX IF NOT EXISTS idx_avatars_style_active ON avatars(style, is_active);
CREATE INDEX IF NOT EXISTS idx_avatars_public_active ON avatars(is_public, is_active);
CREATE INDEX IF NOT EXISTS idx_avatars_created_by ON avatars(created_by);

-- Commento tabella
COMMENT ON TABLE avatars IS 'Avatar 3D per visualizzazione pose da skeleton MediaPipe (75 landmarks)';
COMMENT ON COLUMN avatars.style IS 'Stile marziale: karate, kung_fu, taekwondo, judo, generic';
COMMENT ON COLUMN avatars.rig_type IS 'Tipo armatura: mixamo, readyplayerme, custom';
COMMENT ON COLUMN avatars.has_hand_bones IS 'Se il modello ha bones per dita (21 per mano)';
COMMENT ON COLUMN avatars.license_type IS 'Licenza: cc0, cc_by, proprietary';
