-- ===================================================================
-- Migration: Add Payments & Subscriptions System
-- Version: 002
-- Date: 2025-01-20
-- Description: Stripe integration for stelline purchases, subscriptions, PPV
-- ===================================================================

-- === PAYMENTS TABLE ===

CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Payment details
    provider VARCHAR(20) NOT NULL DEFAULT 'stripe',  -- stripe, paypal, crypto
    transaction_type VARCHAR(30) NOT NULL,  -- stelline_purchase, subscription, video_purchase, donation, withdrawal, refund
    amount_eur INTEGER NOT NULL,  -- Amount in EUR cents
    currency VARCHAR(3) NOT NULL DEFAULT 'EUR',
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending, processing, succeeded, failed, canceled, refunded

    -- Provider IDs
    stripe_payment_intent_id VARCHAR(255) UNIQUE,
    stripe_charge_id VARCHAR(255),
    paypal_order_id VARCHAR(255) UNIQUE,
    blockchain_tx_hash VARCHAR(255) UNIQUE,

    -- Metadata
    stelline_amount INTEGER,  -- If stelline purchase
    video_id UUID REFERENCES videos(id) ON DELETE SET NULL,  -- If PPV
    subscription_id UUID,  -- Will reference subscriptions(id), added after table creation
    description TEXT,
    extra_metadata JSONB,  -- Renamed from 'metadata' to avoid SQLAlchemy reserved word conflict

    -- Error handling
    failure_code VARCHAR(50),
    failure_message TEXT,

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    refunded_at TIMESTAMP
);

CREATE INDEX idx_payment_user_status ON payments(user_id, status);
CREATE INDEX idx_payment_type_status ON payments(transaction_type, status);
CREATE INDEX idx_payment_created ON payments(created_at);
CREATE INDEX idx_payment_stripe_intent ON payments(stripe_payment_intent_id);


-- === SUBSCRIPTIONS TABLE ===

CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,

    -- Subscription details
    tier VARCHAR(50) NOT NULL,  -- HYBRID_LIGHT, HYBRID_STANDARD, PREMIUM, BUSINESS
    status VARCHAR(30) NOT NULL DEFAULT 'incomplete',  -- active, past_due, canceled, incomplete, incomplete_expired, trialing, unpaid

    -- Stripe IDs
    stripe_subscription_id VARCHAR(255) UNIQUE,
    stripe_customer_id VARCHAR(255),
    stripe_price_id VARCHAR(255),

    -- Billing
    amount_eur_cents INTEGER NOT NULL,
    interval VARCHAR(20) NOT NULL DEFAULT 'month',  -- month, year

    -- Trial
    trial_start TIMESTAMP,
    trial_end TIMESTAMP,

    -- Billing period
    current_period_start TIMESTAMP,
    current_period_end TIMESTAMP,

    -- Cancellation
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
    canceled_at TIMESTAMP,
    cancellation_reason TEXT,

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_subscription_user ON subscriptions(user_id);
CREATE INDEX idx_subscription_status ON subscriptions(status, created_at);
CREATE INDEX idx_subscription_stripe ON subscriptions(stripe_subscription_id);


-- === ADD FOREIGN KEY FOR subscription_id IN payments ===
ALTER TABLE payments
ADD CONSTRAINT fk_payments_subscription
FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL;


-- === STELLINE PURCHASES TABLE ===

CREATE TABLE stelline_purchases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    payment_id UUID NOT NULL REFERENCES payments(id) ON DELETE CASCADE,

    -- Purchase details
    package_type VARCHAR(20) NOT NULL,  -- small, medium, large
    stelline_amount INTEGER NOT NULL,
    price_eur_cents INTEGER NOT NULL,

    -- Status
    delivered BOOLEAN NOT NULL DEFAULT false,
    delivered_at TIMESTAMP,

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_stelline_purchase_user ON stelline_purchases(user_id, created_at);
CREATE INDEX idx_stelline_purchase_payment ON stelline_purchases(payment_id);


-- === VIDEO PURCHASES TABLE (PAY-PER-VIEW) ===

CREATE TABLE video_purchases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
    payment_id UUID NOT NULL REFERENCES payments(id) ON DELETE CASCADE,

    -- Purchase details
    price_stelline INTEGER NOT NULL,

    -- Access
    access_granted BOOLEAN NOT NULL DEFAULT false,
    access_expires_at TIMESTAMP,  -- NULL = lifetime access

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_video_purchase_user_video ON video_purchases(user_id, video_id);
CREATE INDEX idx_video_purchase_payment ON video_purchases(payment_id);


-- === ADD STRIPE CUSTOMER ID TO USERS TABLE ===

ALTER TABLE users
ADD COLUMN stripe_customer_id VARCHAR(255) UNIQUE;

CREATE INDEX idx_users_stripe_customer ON users(stripe_customer_id);


-- === VERIFY MIGRATION ===

DO $$
BEGIN
    -- Check all tables exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'payments') THEN
        RAISE EXCEPTION 'Migration failed: payments table not created';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'subscriptions') THEN
        RAISE EXCEPTION 'Migration failed: subscriptions table not created';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'stelline_purchases') THEN
        RAISE EXCEPTION 'Migration failed: stelline_purchases table not created';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'video_purchases') THEN
        RAISE EXCEPTION 'Migration failed: video_purchases table not created';
    END IF;

    RAISE NOTICE 'Migration 002 completed successfully!';
END $$;
