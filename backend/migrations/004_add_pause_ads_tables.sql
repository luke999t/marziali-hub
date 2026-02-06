-- ========================================
-- Migration: Pause Ads System (Netflix-style)
-- Version: 004
-- Date: 2025-12-08
-- Description: Aggiunge sistema pause ads con overlay 50/50 e tracking blockchain
-- ========================================

-- ========================================
-- STEP 1: Tabella PAUSE_ADS
-- Inventory sponsor ads per pause overlay
-- ========================================

CREATE TABLE IF NOT EXISTS pause_ads (
    -- Primary key (string per supportare ID da seed JSON)
    id VARCHAR(100) PRIMARY KEY,
    
    -- === ADVERTISER INFO ===
    advertiser_name VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    
    -- === CREATIVE ASSETS ===
    image_url TEXT NOT NULL,  -- 600x400 recommended
    click_url TEXT NOT NULL,  -- Destination URL
    
    -- === PRICING ===
    cpm_rate FLOAT NOT NULL DEFAULT 5.0,  -- EUR per 1000 impressions
    
    -- === TARGETING ===
    -- JSON arrays per flessibilità
    target_tiers TEXT DEFAULT '["FREE", "HYBRID_LIGHT", "HYBRID_STANDARD"]',
    target_styles TEXT,  -- NULL = tutti, altrimenti JSON array ["karate", "judo"]
    target_countries TEXT DEFAULT '["IT"]',
    
    -- === STATUS ===
    is_active BOOLEAN NOT NULL DEFAULT true,
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP NOT NULL,
    
    -- === BUDGET ===
    budget_total FLOAT DEFAULT 1000.0,
    budget_remaining FLOAT DEFAULT 1000.0,
    daily_cap INTEGER DEFAULT 10000,  -- Max impressions/day
    
    -- === ANALYTICS ===
    impressions INTEGER NOT NULL DEFAULT 0,
    clicks INTEGER NOT NULL DEFAULT 0,
    total_revenue FLOAT NOT NULL DEFAULT 0.0,
    
    -- === METADATA ===
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indici per performance
CREATE INDEX IF NOT EXISTS idx_pause_ads_active_dates 
ON pause_ads(is_active, start_date, end_date);

CREATE INDEX IF NOT EXISTS idx_pause_ads_advertiser 
ON pause_ads(advertiser_name);

CREATE INDEX IF NOT EXISTS idx_pause_ads_cpm 
ON pause_ads(cpm_rate);

-- Commenti
COMMENT ON TABLE pause_ads IS 'Inventory sponsor ads per Netflix-style pause overlay';
COMMENT ON COLUMN pause_ads.cpm_rate IS 'Cost Per Mille - EUR per 1000 impressions (default €5.00)';
COMMENT ON COLUMN pause_ads.target_tiers IS 'JSON array tier utenti: FREE, HYBRID_LIGHT, HYBRID_STANDARD';
COMMENT ON COLUMN pause_ads.target_styles IS 'JSON array stili arti marziali, NULL per tutti';

-- ========================================
-- STEP 2: Tabella PAUSE_AD_IMPRESSIONS
-- Tracking granulare per billing e blockchain
-- ========================================

CREATE TABLE IF NOT EXISTS pause_ad_impressions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- === FOREIGN KEYS ===
    pause_ad_id VARCHAR(100) REFERENCES pause_ads(id) ON DELETE SET NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    video_id UUID REFERENCES videos(id) ON DELETE SET NULL,
    
    -- === IMPRESSION TYPE ===
    impression_type VARCHAR(20) DEFAULT 'pause' NOT NULL,
    -- Types: "pause" (overlay shown), "resume" (user resumed), "skip" (user dismissed)
    
    -- === CLICK DATA ===
    clicked BOOLEAN DEFAULT false NOT NULL,
    click_type VARCHAR(20),
    -- Click types: "ad" (clicked sponsor), "suggested" (clicked suggested video), null
    
    -- === BLOCKCHAIN BATCH ===
    included_in_batch BOOLEAN DEFAULT false NOT NULL,
    batch_id UUID REFERENCES blockchain_batches(id) ON DELETE SET NULL,
    
    -- === METADATA ===
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    ip_address VARCHAR(50),
    user_agent TEXT,
    device_type VARCHAR(20),  -- "mobile", "tablet", "desktop"
    
    -- === REVENUE TRACKING ===
    impression_revenue FLOAT DEFAULT 0.005 NOT NULL,  -- CPM/1000
    click_revenue FLOAT DEFAULT 0.0 NOT NULL  -- €0.02 if clicked
);

-- Indici per performance
CREATE INDEX IF NOT EXISTS idx_pause_impressions_user 
ON pause_ad_impressions(user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_pause_impressions_ad 
ON pause_ad_impressions(pause_ad_id, created_at);

CREATE INDEX IF NOT EXISTS idx_pause_impressions_batch 
ON pause_ad_impressions(included_in_batch, created_at);

CREATE INDEX IF NOT EXISTS idx_pause_impressions_clicks 
ON pause_ad_impressions(clicked, click_type);

-- Commenti
COMMENT ON TABLE pause_ad_impressions IS 'Granular tracking impressions per billing e blockchain audit';
COMMENT ON COLUMN pause_ad_impressions.impression_type IS 'pause/resume/skip';
COMMENT ON COLUMN pause_ad_impressions.click_type IS 'ad/suggested/null';
COMMENT ON COLUMN pause_ad_impressions.impression_revenue IS 'Base revenue: CPM/1000 = €0.005';
COMMENT ON COLUMN pause_ad_impressions.click_revenue IS 'Click bonus: €0.02 if clicked on ad';

-- ========================================
-- STEP 3: Trigger per UPDATE timestamp
-- ========================================

-- Funzione per update timestamp (se non esiste già)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger per pause_ads
DROP TRIGGER IF EXISTS update_pause_ads_updated_at ON pause_ads;
CREATE TRIGGER update_pause_ads_updated_at
    BEFORE UPDATE ON pause_ads
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ========================================
-- STEP 4: Views per Analytics
-- ========================================

-- View per statistiche pause ads
CREATE OR REPLACE VIEW pause_ads_stats AS
SELECT 
    pa.id,
    pa.advertiser_name,
    pa.title,
    pa.impressions,
    pa.clicks,
    pa.total_revenue,
    CASE 
        WHEN pa.impressions > 0 
        THEN ROUND((pa.clicks::FLOAT / pa.impressions * 100)::NUMERIC, 2)
        ELSE 0 
    END AS ctr_percent,
    CASE 
        WHEN pa.impressions > 0 
        THEN ROUND((pa.total_revenue / pa.impressions * 1000)::NUMERIC, 2)
        ELSE 0 
    END AS effective_cpm,
    pa.budget_remaining,
    pa.is_active,
    pa.start_date,
    pa.end_date
FROM pause_ads pa
ORDER BY pa.impressions DESC;

COMMENT ON VIEW pause_ads_stats IS 'Statistiche aggregate pause ads con CTR e eCPM';

-- View per impressions da aggregare in blockchain
CREATE OR REPLACE VIEW pause_impressions_for_blockchain AS
SELECT 
    DATE_TRUNC('week', pai.created_at) AS week_start,
    COUNT(*) AS total_impressions,
    COUNT(DISTINCT pai.user_id) AS unique_users,
    SUM(CASE WHEN pai.clicked THEN 1 ELSE 0 END) AS total_clicks,
    SUM(pai.impression_revenue + pai.click_revenue) AS total_revenue,
    COUNT(DISTINCT pai.pause_ad_id) AS unique_ads
FROM pause_ad_impressions pai
WHERE pai.included_in_batch = false
GROUP BY DATE_TRUNC('week', pai.created_at)
ORDER BY week_start DESC;

COMMENT ON VIEW pause_impressions_for_blockchain IS 'Aggregazione settimanale impressions per blockchain batch';

-- ========================================
-- ROLLBACK SCRIPT
-- ========================================

/*
-- ATTENZIONE: Questo elimina TUTTI i dati pause ads!
-- Eseguire solo in caso di rollback necessario

DROP VIEW IF EXISTS pause_impressions_for_blockchain;
DROP VIEW IF EXISTS pause_ads_stats;
DROP TRIGGER IF EXISTS update_pause_ads_updated_at ON pause_ads;
DROP TABLE IF EXISTS pause_ad_impressions;
DROP TABLE IF EXISTS pause_ads;
*/

-- ========================================
-- VERIFICA POST-MIGRATION
-- ========================================

-- Verifica tabelle create
SELECT table_name 
FROM information_schema.tables 
WHERE table_name IN ('pause_ads', 'pause_ad_impressions')
ORDER BY table_name;

-- Verifica indici
SELECT indexname, tablename 
FROM pg_indexes 
WHERE tablename IN ('pause_ads', 'pause_ad_impressions')
ORDER BY tablename, indexname;

-- Verifica views
SELECT table_name 
FROM information_schema.views 
WHERE table_name IN ('pause_ads_stats', 'pause_impressions_for_blockchain');

-- ========================================
-- FINE MIGRATION
-- ========================================
