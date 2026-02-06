-- Migration: Add missing columns to users table
-- Date: 2026-01-10
-- Issue: Column 'tier' and other subscription columns don't exist

-- Create UserTier enum type if not exists
DO $$ BEGIN
    CREATE TYPE usertier AS ENUM ('free', 'hybrid_light', 'hybrid_standard', 'premium', 'pay_per_view', 'business');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Add missing columns to users table
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tier usertier DEFAULT 'free' NOT NULL,
    ADD COLUMN IF NOT EXISTS subscription_end TIMESTAMP,
    ADD COLUMN IF NOT EXISTS auto_renew BOOLEAN DEFAULT TRUE NOT NULL,
    ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(100) UNIQUE,
    ADD COLUMN IF NOT EXISTS ads_unlocked_videos INTEGER DEFAULT 0 NOT NULL,
    ADD COLUMN IF NOT EXISTS ads_unlock_valid_until TIMESTAMP,
    ADD COLUMN IF NOT EXISTS language_preference VARCHAR(10) DEFAULT 'it' NOT NULL,
    ADD COLUMN IF NOT EXISTS subtitle_preference VARCHAR(10),
    ADD COLUMN IF NOT EXISTS quality_preference VARCHAR(10) DEFAULT 'auto' NOT NULL,
    ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP;

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_tier_active ON users(tier, is_active);
CREATE INDEX IF NOT EXISTS idx_users_tier ON users(tier);

-- Verify
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_name = 'users'
ORDER BY ordinal_position;
