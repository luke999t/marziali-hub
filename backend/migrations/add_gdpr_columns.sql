-- Migration: Add GDPR consent columns to event_subscriptions
-- Date: 2026-01-12
-- Purpose: GDPR compliance for event subscriptions

-- Add GDPR consent columns
ALTER TABLE event_subscriptions
ADD COLUMN IF NOT EXISTS gdpr_consent BOOLEAN DEFAULT FALSE NOT NULL;

ALTER TABLE event_subscriptions
ADD COLUMN IF NOT EXISTS gdpr_consent_at TIMESTAMP;

ALTER TABLE event_subscriptions
ADD COLUMN IF NOT EXISTS gdpr_consent_ip VARCHAR(45);

ALTER TABLE event_subscriptions
ADD COLUMN IF NOT EXISTS marketing_consent BOOLEAN DEFAULT FALSE NOT NULL;

ALTER TABLE event_subscriptions
ADD COLUMN IF NOT EXISTS marketing_consent_at TIMESTAMP;

-- Verify columns were added
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_name = 'event_subscriptions'
AND column_name LIKE '%consent%'
ORDER BY ordinal_position;
