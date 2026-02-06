-- =====================================================
-- Migration 006: Add Special Projects Voting Tables
-- AI_MODULE: Special Projects Migration
-- AI_DESCRIPTION: Creates tables for voting system
-- Date: 2025-12-17
-- =====================================================

-- ==================== ENUM TYPES ====================

-- Project Status enum
DO $$ BEGIN
    CREATE TYPE project_status AS ENUM (
        'draft',
        'active',
        'voting_closed',
        'approved',
        'in_progress',
        'completed',
        'rejected',
        'archived'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Eligibility Status enum
DO $$ BEGIN
    CREATE TYPE eligibility_status AS ENUM (
        'eligible',
        'not_eligible',
        'pending',
        'suspended'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- ==================== TABLES ====================

-- 1. Special Projects Table
CREATE TABLE IF NOT EXISTS special_projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Content
    title VARCHAR(200) NOT NULL,
    slug VARCHAR(200) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    short_description VARCHAR(500),

    -- Media
    image_url TEXT,
    video_url TEXT,

    -- Budget & Timeline
    estimated_budget_cents INTEGER,
    estimated_days INTEGER,
    funding_goal_cents INTEGER,
    current_funding_cents INTEGER DEFAULT 0 NOT NULL,

    -- Status
    status project_status DEFAULT 'draft' NOT NULL,

    -- Voting Period
    voting_start_date TIMESTAMP,
    voting_end_date TIMESTAMP,

    -- Vote Stats (denormalized for performance)
    total_votes INTEGER DEFAULT 0 NOT NULL,
    total_weighted_votes INTEGER DEFAULT 0 NOT NULL,
    unique_voters INTEGER DEFAULT 0 NOT NULL,

    -- Creator
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP,
    completed_at TIMESTAMP,

    -- Soft Delete
    is_deleted BOOLEAN DEFAULT FALSE NOT NULL,
    deleted_at TIMESTAMP,

    -- Extra Data (JSONB for PostgreSQL flexibility)
    metadata_json JSONB,
    tags JSONB,

    -- Constraints
    CONSTRAINT check_positive_votes CHECK (total_votes >= 0),
    CONSTRAINT check_positive_weighted CHECK (total_weighted_votes >= 0),
    CONSTRAINT check_budget_positive CHECK (estimated_budget_cents IS NULL OR estimated_budget_cents >= 0),
    CONSTRAINT check_funding_positive CHECK (funding_goal_cents IS NULL OR funding_goal_cents >= 0)
);

-- 2. Project Votes Table
CREATE TABLE IF NOT EXISTS special_project_votes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- References
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES special_projects(id) ON DELETE CASCADE,

    -- Vote Data
    vote_weight INTEGER NOT NULL,
    subscription_tier_at_vote VARCHAR(50) NOT NULL,

    -- Cycle (format: YYYY-MM)
    vote_cycle VARCHAR(20) NOT NULL,

    -- Status
    is_active BOOLEAN DEFAULT TRUE NOT NULL,

    -- Timestamps
    voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Previous Vote (for tracking changes)
    previous_project_id UUID,
    changed_from_previous BOOLEAN DEFAULT FALSE NOT NULL,

    -- Constraints
    CONSTRAINT check_positive_weight CHECK (vote_weight >= 0)
);

-- Unique constraint: one active vote per user per cycle
-- Note: This allows multiple inactive votes (history)
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_cycle_active_vote
ON special_project_votes (user_id, vote_cycle)
WHERE is_active = TRUE;

-- 3. Voting Eligibility Table
CREATE TABLE IF NOT EXISTS special_projects_eligibility (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Eligibility
    status eligibility_status DEFAULT 'not_eligible' NOT NULL,
    vote_weight INTEGER DEFAULT 0 NOT NULL,
    subscription_tier VARCHAR(50) NOT NULL,

    -- Metrics (for free users)
    watch_minutes_current INTEGER DEFAULT 0 NOT NULL,
    ads_watched_current INTEGER DEFAULT 0 NOT NULL,
    videos_completed_current INTEGER DEFAULT 0 NOT NULL,

    -- Thresholds (snapshot at calculation)
    watch_minutes_required INTEGER,
    ads_watched_required INTEGER,
    videos_completed_required INTEGER,

    -- Progress (for UI)
    progress_percent FLOAT DEFAULT 0.0 NOT NULL,

    -- Cycle
    vote_cycle VARCHAR(20) NOT NULL,

    -- Timestamps
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    valid_until TIMESTAMP,

    -- Reason
    ineligibility_reason VARCHAR(255),

    -- Constraints
    CONSTRAINT uq_user_eligibility_cycle UNIQUE (user_id, vote_cycle)
);

-- 4. Config Table
CREATE TABLE IF NOT EXISTS special_projects_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(100) NOT NULL UNIQUE,

    -- Value
    config_value JSONB NOT NULL,
    value_type VARCHAR(20) NOT NULL,

    -- Metadata
    description TEXT,
    updated_by UUID,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

    -- Audit
    previous_value JSONB,
    change_reason TEXT
);

-- 5. Vote History Table
CREATE TABLE IF NOT EXISTS special_projects_vote_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,

    -- Change Details
    from_project_id UUID,
    to_project_id UUID NOT NULL,
    vote_cycle VARCHAR(20) NOT NULL,

    -- Context
    vote_weight INTEGER NOT NULL,
    subscription_tier VARCHAR(50) NOT NULL,

    -- Timestamp
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- ==================== INDEXES ====================

-- Projects
CREATE INDEX IF NOT EXISTS idx_project_status ON special_projects (status);
CREATE INDEX IF NOT EXISTS idx_project_slug ON special_projects (slug);
CREATE INDEX IF NOT EXISTS idx_project_title ON special_projects (title);
CREATE INDEX IF NOT EXISTS idx_project_created_by ON special_projects (created_by);
CREATE INDEX IF NOT EXISTS idx_project_status_voting ON special_projects (status, voting_start_date, voting_end_date);
CREATE INDEX IF NOT EXISTS idx_project_votes ON special_projects (total_weighted_votes, status);
CREATE INDEX IF NOT EXISTS idx_project_not_deleted ON special_projects (is_deleted) WHERE is_deleted = FALSE;

-- Votes
CREATE INDEX IF NOT EXISTS idx_vote_user ON special_project_votes (user_id);
CREATE INDEX IF NOT EXISTS idx_vote_project ON special_project_votes (project_id);
CREATE INDEX IF NOT EXISTS idx_vote_cycle ON special_project_votes (vote_cycle);
CREATE INDEX IF NOT EXISTS idx_vote_project_cycle ON special_project_votes (project_id, vote_cycle, is_active);
CREATE INDEX IF NOT EXISTS idx_vote_user_active ON special_project_votes (user_id, is_active);

-- Eligibility
CREATE INDEX IF NOT EXISTS idx_eligibility_user ON special_projects_eligibility (user_id);
CREATE INDEX IF NOT EXISTS idx_eligibility_cycle ON special_projects_eligibility (vote_cycle);
CREATE INDEX IF NOT EXISTS idx_eligibility_status ON special_projects_eligibility (status, vote_cycle);

-- Config
CREATE INDEX IF NOT EXISTS idx_config_key ON special_projects_config (config_key);

-- Vote History
CREATE INDEX IF NOT EXISTS idx_vote_history_user ON special_projects_vote_history (user_id);
CREATE INDEX IF NOT EXISTS idx_vote_history_cycle ON special_projects_vote_history (vote_cycle);
CREATE INDEX IF NOT EXISTS idx_vote_history_user_cycle ON special_projects_vote_history (user_id, vote_cycle);
CREATE INDEX IF NOT EXISTS idx_vote_history_changed_at ON special_projects_vote_history (changed_at);

-- ==================== TRIGGERS ====================

-- Updated_at trigger function (reuse if exists)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Auto-update updated_at for special_projects
DROP TRIGGER IF EXISTS update_special_projects_updated_at ON special_projects;
CREATE TRIGGER update_special_projects_updated_at
    BEFORE UPDATE ON special_projects
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Auto-update updated_at for special_project_votes
DROP TRIGGER IF EXISTS update_special_project_votes_updated_at ON special_project_votes;
CREATE TRIGGER update_special_project_votes_updated_at
    BEFORE UPDATE ON special_project_votes
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Auto-update updated_at for config
DROP TRIGGER IF EXISTS update_special_projects_config_updated_at ON special_projects_config;
CREATE TRIGGER update_special_projects_config_updated_at
    BEFORE UPDATE ON special_projects_config
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ==================== DEFAULT CONFIG DATA ====================

INSERT INTO special_projects_config (config_key, config_value, value_type, description) VALUES
    ('vote_weight_premium_full', '3', 'int', 'Vote weight for premium full subscribers'),
    ('vote_weight_premium_hybrid', '2', 'int', 'Vote weight for hybrid subscribers'),
    ('vote_weight_free_with_ads', '1', 'int', 'Vote weight for free users who meet requirements'),
    ('vote_weight_free_no_ads', '0', 'int', 'Vote weight for free users (cannot vote)'),
    ('free_min_watch_minutes', '60', 'int', 'Minimum watch minutes for free users to vote'),
    ('free_min_ads_watched', '10', 'int', 'Minimum ads watched for free users to vote'),
    ('free_min_videos_completed', '5', 'int', 'Minimum videos completed for free users to vote'),
    ('votes_per_user_per_cycle', '1', 'int', 'Number of votes per user per cycle'),
    ('can_change_vote_same_cycle', 'false', 'bool', 'Whether users can change vote in same cycle'),
    ('vote_persists_next_cycle', 'true', 'bool', 'Whether vote persists to next cycle if not changed')
ON CONFLICT (config_key) DO NOTHING;

-- ==================== VERIFICATION ====================

-- Verify tables created
DO $$
DECLARE
    table_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO table_count
    FROM information_schema.tables
    WHERE table_schema = 'public'
    AND table_name IN (
        'special_projects',
        'special_project_votes',
        'special_projects_eligibility',
        'special_projects_config',
        'special_projects_vote_history'
    );

    IF table_count = 5 THEN
        RAISE NOTICE '✅ Migration 006 completed: All 5 special projects tables created';
    ELSE
        RAISE WARNING '⚠️ Migration 006: Only % of 5 tables found', table_count;
    END IF;
END $$;
