-- Migration 005: Add Royalties Blockchain System Tables
-- Date: 2025-12-16
-- Description: Creates tables for parametrizable royalty tracking with blockchain integration
--
-- AI_MODULE: Royalties Migration
-- AI_DESCRIPTION: Database schema per sistema royalties parametrizzabile
-- AI_BUSINESS: Storage persistente royalties, payouts, subscriptions
-- AI_TEACHING: SQL DDL, indexes, constraints, enum types

-- ======================== ENUM TYPES ========================

-- Pricing model for master content
DO $$ BEGIN
    CREATE TYPE pricing_model AS ENUM ('free', 'included', 'premium', 'custom');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Payout method preferences
DO $$ BEGIN
    CREATE TYPE payout_method AS ENUM ('blockchain', 'stripe', 'bank', 'paypal');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Payout status
DO $$ BEGIN
    CREATE TYPE payout_status AS ENUM ('pending', 'processing', 'completed', 'failed', 'cancelled');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Subscription type
DO $$ BEGIN
    CREATE TYPE royalty_subscription_type AS ENUM ('platform', 'master', 'per_video');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Royalty milestone
DO $$ BEGIN
    CREATE TYPE royalty_milestone AS ENUM ('started', '25', '50', '75', 'completed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ======================== MASTER PROFILES TABLE ========================

CREATE TABLE IF NOT EXISTS royalty_master_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    maestro_id UUID REFERENCES maestros(id) ON DELETE CASCADE,

    -- Pricing model
    pricing_model pricing_model NOT NULL DEFAULT 'included',
    custom_prices JSONB,  -- Override prices per subscription type
    royalty_override JSONB,  -- Override royalty split percentages
    milestone_override JSONB,  -- Override milestone amounts

    -- Payment settings
    wallet_address VARCHAR(42),  -- Ethereum address
    payout_method payout_method NOT NULL DEFAULT 'stripe',
    min_payout_override INTEGER,  -- Override minimum payout in cents

    -- Banking fallback
    iban VARCHAR(34),
    paypal_email VARCHAR(255),
    stripe_connect_account_id VARCHAR(100),

    -- Status
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    verified_for_payouts BOOLEAN NOT NULL DEFAULT FALSE,
    verification_date TIMESTAMP,

    -- Stats (denormalized for performance)
    total_views INTEGER NOT NULL DEFAULT 0,
    total_royalties_cents INTEGER NOT NULL DEFAULT 0,
    total_paid_out_cents INTEGER NOT NULL DEFAULT 0,
    pending_payout_cents INTEGER NOT NULL DEFAULT 0,
    total_subscribers INTEGER NOT NULL DEFAULT 0,

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_payout_at TIMESTAMP,

    -- Constraints
    CONSTRAINT valid_wallet_address CHECK (
        wallet_address IS NULL OR
        (wallet_address LIKE '0x%' AND LENGTH(wallet_address) = 42)
    )
);

-- Indexes for master profiles
CREATE INDEX IF NOT EXISTS idx_royalty_master_user ON royalty_master_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_royalty_master_pricing ON royalty_master_profiles(pricing_model, is_active);
CREATE INDEX IF NOT EXISTS idx_royalty_master_pending ON royalty_master_profiles(pending_payout_cents, is_active);

-- ======================== STUDENT SUBSCRIPTIONS TABLE ========================

CREATE TABLE IF NOT EXISTS royalty_student_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    master_id UUID REFERENCES royalty_master_profiles(id) ON DELETE SET NULL,

    -- Subscription details
    subscription_type royalty_subscription_type NOT NULL,
    subscription_tier VARCHAR(50) NOT NULL,  -- monthly, yearly, lifetime, per_video
    price_paid_cents INTEGER NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'EUR',

    -- Dates
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,  -- NULL = lifetime
    cancelled_at TIMESTAMP,

    -- Renewal
    auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
    renewal_price_cents INTEGER,

    -- Payment
    stripe_subscription_id VARCHAR(100),
    stripe_payment_intent_id VARCHAR(100),

    -- Video specific (for per_video type)
    video_id UUID REFERENCES videos(id) ON DELETE SET NULL,

    -- Status
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for subscriptions
CREATE INDEX IF NOT EXISTS idx_subscription_student ON royalty_student_subscriptions(student_id);
CREATE INDEX IF NOT EXISTS idx_subscription_master ON royalty_student_subscriptions(master_id);
CREATE INDEX IF NOT EXISTS idx_subscription_active ON royalty_student_subscriptions(is_active, expires_at);
CREATE INDEX IF NOT EXISTS idx_subscription_student_master ON royalty_student_subscriptions(student_id, master_id, is_active);
CREATE INDEX IF NOT EXISTS idx_subscription_stripe ON royalty_student_subscriptions(stripe_subscription_id);

-- ======================== VIEW ROYALTIES TABLE ========================

CREATE TABLE IF NOT EXISTS royalty_view_royalties (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- References
    video_id UUID REFERENCES videos(id) ON DELETE SET NULL,
    master_id UUID NOT NULL REFERENCES royalty_master_profiles(id) ON DELETE CASCADE,
    student_id UUID REFERENCES users(id) ON DELETE SET NULL,
    view_session_id UUID NOT NULL,

    -- Milestone
    milestone royalty_milestone NOT NULL,

    -- Amounts (all in cents)
    gross_amount_cents INTEGER NOT NULL,
    platform_fee_cents INTEGER NOT NULL,
    master_amount_cents INTEGER NOT NULL,

    -- Blockchain
    blockchain_batch_id UUID,
    blockchain_tx_hash VARCHAR(66),
    blockchain_verified BOOLEAN NOT NULL DEFAULT FALSE,

    -- Settlement
    settled BOOLEAN NOT NULL DEFAULT FALSE,
    settled_at TIMESTAMP,
    payout_id UUID,

    -- Fraud detection
    fraud_score REAL NOT NULL DEFAULT 0.0,
    flagged_suspicious BOOLEAN NOT NULL DEFAULT FALSE,
    flag_reason VARCHAR(255),

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    video_duration_seconds INTEGER,
    watch_time_seconds INTEGER,

    -- Context
    ip_hash VARCHAR(64),
    device_fingerprint VARCHAR(64),
    country_code VARCHAR(2),

    -- Unique constraint: one milestone per session
    CONSTRAINT uq_session_milestone UNIQUE (view_session_id, milestone)
);

-- Indexes for view royalties
CREATE INDEX IF NOT EXISTS idx_royalty_master ON royalty_view_royalties(master_id);
CREATE INDEX IF NOT EXISTS idx_royalty_video ON royalty_view_royalties(video_id);
CREATE INDEX IF NOT EXISTS idx_royalty_student ON royalty_view_royalties(student_id);
CREATE INDEX IF NOT EXISTS idx_royalty_session ON royalty_view_royalties(view_session_id, milestone);
CREATE INDEX IF NOT EXISTS idx_royalty_unsettled ON royalty_view_royalties(settled, master_id, created_at);
CREATE INDEX IF NOT EXISTS idx_royalty_blockchain ON royalty_view_royalties(blockchain_batch_id, blockchain_verified);
CREATE INDEX IF NOT EXISTS idx_royalty_fraud ON royalty_view_royalties(flagged_suspicious, fraud_score);
CREATE INDEX IF NOT EXISTS idx_royalty_created ON royalty_view_royalties(created_at);

-- ======================== PAYOUTS TABLE ========================

CREATE TABLE IF NOT EXISTS royalty_payouts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    master_id UUID NOT NULL REFERENCES royalty_master_profiles(id) ON DELETE CASCADE,

    -- Amounts
    gross_amount_cents INTEGER NOT NULL,
    fees_cents INTEGER NOT NULL DEFAULT 0,
    net_amount_cents INTEGER NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'EUR',

    -- Period
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    views_count INTEGER NOT NULL DEFAULT 0,

    -- Payment method
    method payout_method NOT NULL,

    -- Blockchain (if method = blockchain)
    blockchain_tx_hash VARCHAR(66),
    blockchain_network VARCHAR(20),
    blockchain_confirmations INTEGER NOT NULL DEFAULT 0,
    wallet_address VARCHAR(42),

    -- Stripe (if method = stripe)
    stripe_transfer_id VARCHAR(100),
    stripe_payout_id VARCHAR(100),

    -- Bank (if method = bank)
    bank_reference VARCHAR(100),
    iban VARCHAR(34),

    -- Status
    status payout_status NOT NULL DEFAULT 'pending',
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    requested_at TIMESTAMP,
    processed_at TIMESTAMP,
    completed_at TIMESTAMP,
    failed_at TIMESTAMP,

    -- Admin
    approved_by UUID,
    notes TEXT
);

-- Indexes for payouts
CREATE INDEX IF NOT EXISTS idx_payout_master ON royalty_payouts(master_id);
CREATE INDEX IF NOT EXISTS idx_payout_status ON royalty_payouts(status, created_at);
CREATE INDEX IF NOT EXISTS idx_payout_master_status ON royalty_payouts(master_id, status);
CREATE INDEX IF NOT EXISTS idx_payout_period ON royalty_payouts(period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_payout_blockchain ON royalty_payouts(blockchain_tx_hash);

-- Add foreign key from view_royalties to payouts
ALTER TABLE royalty_view_royalties
    ADD CONSTRAINT fk_royalty_payout
    FOREIGN KEY (payout_id) REFERENCES royalty_payouts(id) ON DELETE SET NULL;

-- ======================== BLOCKCHAIN BATCHES TABLE ========================

CREATE TABLE IF NOT EXISTS royalty_blockchain_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Merkle tree
    merkle_root VARCHAR(66) NOT NULL,
    merkle_tree_json JSONB,
    leaves_count INTEGER NOT NULL,

    -- Totals
    total_views INTEGER NOT NULL,
    total_amount_cents INTEGER NOT NULL,

    -- Blockchain
    tx_hash VARCHAR(66),
    blockchain_batch_id INTEGER,
    blockchain_network VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    confirmations INTEGER NOT NULL DEFAULT 0,

    -- Gas
    gas_used INTEGER,
    gas_price_gwei NUMERIC(10, 2),
    gas_cost_cents INTEGER,

    -- IPFS
    ipfs_hash VARCHAR(100),
    ipfs_pinned BOOLEAN NOT NULL DEFAULT FALSE,

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    submitted_at TIMESTAMP,
    confirmed_at TIMESTAMP
);

-- Indexes for blockchain batches
CREATE INDEX IF NOT EXISTS idx_batch_status ON royalty_blockchain_batches(status, created_at);
CREATE INDEX IF NOT EXISTS idx_batch_merkle ON royalty_blockchain_batches(merkle_root);
CREATE INDEX IF NOT EXISTS idx_batch_tx ON royalty_blockchain_batches(tx_hash);

-- ======================== MASTER SWITCH HISTORY TABLE ========================

CREATE TABLE IF NOT EXISTS royalty_master_switch_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Switch details
    from_master_id UUID,
    to_master_id UUID NOT NULL,
    switched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Reason
    reason VARCHAR(255)
);

-- Indexes for switch history
CREATE INDEX IF NOT EXISTS idx_switch_student ON royalty_master_switch_history(student_id, switched_at);

-- ======================== UPDATE TRIGGERS ========================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_royalty_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to tables with updated_at
DROP TRIGGER IF EXISTS trigger_royalty_master_updated ON royalty_master_profiles;
CREATE TRIGGER trigger_royalty_master_updated
    BEFORE UPDATE ON royalty_master_profiles
    FOR EACH ROW EXECUTE FUNCTION update_royalty_updated_at();

DROP TRIGGER IF EXISTS trigger_royalty_subscription_updated ON royalty_student_subscriptions;
CREATE TRIGGER trigger_royalty_subscription_updated
    BEFORE UPDATE ON royalty_student_subscriptions
    FOR EACH ROW EXECUTE FUNCTION update_royalty_updated_at();

-- ======================== COMMENTS ========================

COMMENT ON TABLE royalty_master_profiles IS 'Master profiles for royalty tracking with custom pricing and payout settings';
COMMENT ON TABLE royalty_student_subscriptions IS 'Student subscriptions to platform or specific masters';
COMMENT ON TABLE royalty_view_royalties IS 'Individual view royalties with milestone tracking';
COMMENT ON TABLE royalty_payouts IS 'Payout records for settled royalties';
COMMENT ON TABLE royalty_blockchain_batches IS 'Blockchain batch submissions with Merkle proofs';
COMMENT ON TABLE royalty_master_switch_history IS 'History of student master switches for cooldown enforcement';

-- ======================== MIGRATION COMPLETE ========================
-- Run: psql -d martial_arts_db -f 005_add_royalties_tables.sql
