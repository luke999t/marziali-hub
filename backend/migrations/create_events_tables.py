"""
AI_MODULE: Events/ASD Migration
AI_DESCRIPTION: Migration script per creare tabelle modulo eventi
AI_BUSINESS: Struttura DB per eventi ASD (90% ricavi LIBRA)
AI_TEACHING: PostgreSQL DDL, ENUM types, JSONB, ARRAY, indexes

Run: python migrations/create_events_tables.py

TABLES CREATED:
1. asd_partners - ASD partner con Stripe Connect
2. events - Eventi con presale, bundle, capacita
3. event_options - Opzioni evento (pranzo, tshirt, etc.)
4. event_subscriptions - Iscrizioni con split payment
5. event_waiting_list - Waiting list "notify all"
6. asd_refund_requests - Richieste rimborso
7. platform_alert_config - Config alert piattaforma
8. event_notifications - Notifiche schedulate
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine

MIGRATION_SQL = """
-- ============================================================
-- ENUM TYPES
-- ============================================================

-- EventStatus enum (events module specific)
DO $$ BEGIN
    CREATE TYPE event_status AS ENUM (
        'draft',
        'presale',
        'open',
        'sold_out',
        'closed',
        'ongoing',
        'completed',
        'cancelled'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- EventSubscriptionStatus enum (different from royalties subscriptionstatus)
DO $$ BEGIN
    CREATE TYPE event_subscription_status AS ENUM (
        'pending',
        'confirmed',
        'cancelled',
        'refunded',
        'no_show',
        'attended'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- EventRefundStatus enum
DO $$ BEGIN
    CREATE TYPE event_refund_status AS ENUM (
        'pending',
        'approved',
        'processed',
        'rejected'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- EventAlertType enum
DO $$ BEGIN
    CREATE TYPE event_alert_type AS ENUM (
        'event_reminder',
        'presale_start',
        'sale_start',
        'low_capacity',
        'threshold_warning',
        'waitlist_spot',
        'refund_request',
        'event_cancelled'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- EventNotificationChannel enum
DO $$ BEGIN
    CREATE TYPE event_notification_channel AS ENUM (
        'email',
        'push',
        'dashboard',
        'sms'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- PresaleCriteriaType enum
DO $$ BEGIN
    CREATE TYPE presale_criteria_type AS ENUM (
        'email_list',
        'subscription_active',
        'course_purchased',
        'learning_path',
        'tier_minimum'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- RefundApprovalMode enum
DO $$ BEGIN
    CREATE TYPE refund_approval_mode AS ENUM (
        'always_required',
        'never_required',
        'per_event'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================
-- TABLE: asd_partners
-- ============================================================
CREATE TABLE IF NOT EXISTS asd_partners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Basic Info
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    logo_url TEXT,
    website VARCHAR(255),

    -- Contact
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(50),
    address TEXT,
    city VARCHAR(100),
    province VARCHAR(10),
    postal_code VARCHAR(10),
    country VARCHAR(100) DEFAULT 'Italia' NOT NULL,

    -- Legal
    fiscal_code VARCHAR(16) UNIQUE,
    vat_number VARCHAR(20),

    -- Admin
    admin_user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Stripe Connect
    stripe_account_id VARCHAR(255) UNIQUE,
    stripe_account_status VARCHAR(50) DEFAULT 'pending' NOT NULL,
    stripe_onboarding_complete BOOLEAN DEFAULT FALSE NOT NULL,

    -- Payment Config
    default_split_percentage FLOAT DEFAULT 85.0 NOT NULL,

    -- Refund Policy
    refund_approval_mode refund_approval_mode DEFAULT 'per_event' NOT NULL,

    -- Status
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE NOT NULL,
    verified_at TIMESTAMP,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_asd_partners_name ON asd_partners(name);
CREATE INDEX IF NOT EXISTS idx_asd_partners_slug ON asd_partners(slug);
CREATE INDEX IF NOT EXISTS idx_asd_partners_admin ON asd_partners(admin_user_id);
CREATE INDEX IF NOT EXISTS idx_asd_partners_stripe ON asd_partners(stripe_account_id);
CREATE INDEX IF NOT EXISTS idx_asd_partners_active ON asd_partners(is_active);

-- ============================================================
-- TABLE: events
-- ============================================================
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asd_id UUID NOT NULL REFERENCES asd_partners(id) ON DELETE CASCADE,

    -- Basic Info
    title VARCHAR(255) NOT NULL,
    slug VARCHAR(150) UNIQUE NOT NULL,
    description TEXT,
    short_description VARCHAR(500),
    cover_image_url TEXT,

    -- Dates
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,

    -- Presale Dates
    presale_start TIMESTAMP,
    presale_end TIMESTAMP,
    sale_start TIMESTAMP,

    -- Capacity
    total_capacity INTEGER NOT NULL CHECK (total_capacity > 0),
    current_subscriptions INTEGER DEFAULT 0 NOT NULL,
    min_threshold INTEGER,

    -- Location
    location_name VARCHAR(255),
    location_address TEXT,
    location_city VARCHAR(100),
    location_country VARCHAR(100) DEFAULT 'Italia' NOT NULL,
    location_coordinates JSONB,

    -- Presale Criteria
    presale_enabled BOOLEAN DEFAULT FALSE NOT NULL,
    presale_criteria JSONB,

    -- Bundle
    bundle_course_id UUID,
    bundle_discount_percent FLOAT DEFAULT 0 NOT NULL,

    -- Payment
    split_percentage FLOAT,

    -- Refund Policy
    requires_refund_approval BOOLEAN,

    -- Alert Config Override
    alert_config_override JSONB,

    -- Status
    status event_status DEFAULT 'draft' NOT NULL,

    -- Metadata
    discipline VARCHAR(100),
    instructor_name VARCHAR(255),
    instructor_bio TEXT,

    -- Audit
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    published_at TIMESTAMP,
    cancelled_at TIMESTAMP,
    cancellation_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

    -- Constraints
    CONSTRAINT check_event_dates CHECK (end_date >= start_date)
);

CREATE INDEX IF NOT EXISTS idx_events_slug ON events(slug);
CREATE INDEX IF NOT EXISTS idx_events_asd ON events(asd_id);
CREATE INDEX IF NOT EXISTS idx_events_start_date ON events(start_date);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
CREATE INDEX IF NOT EXISTS idx_events_asd_status ON events(asd_id, status);
CREATE INDEX IF NOT EXISTS idx_events_dates ON events(start_date, end_date);
CREATE INDEX IF NOT EXISTS idx_events_presale ON events(presale_start, presale_end);

-- ============================================================
-- TABLE: event_options
-- ============================================================
CREATE TABLE IF NOT EXISTS event_options (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,

    -- Option Info
    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Dates (subset of event dates)
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,

    -- Pricing
    price_cents INTEGER NOT NULL,
    early_bird_price_cents INTEGER,
    early_bird_deadline TIMESTAMP,

    -- Bundle Override
    includes_bundle BOOLEAN DEFAULT TRUE NOT NULL,

    -- Status
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    sort_order INTEGER DEFAULT 0 NOT NULL,

    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

    -- Constraints
    CONSTRAINT check_option_dates CHECK (end_date >= start_date)
);

CREATE INDEX IF NOT EXISTS idx_event_options_event ON event_options(event_id);
CREATE INDEX IF NOT EXISTS idx_event_options_event_active ON event_options(event_id, is_active);

-- ============================================================
-- TABLE: event_subscriptions
-- ============================================================
CREATE TABLE IF NOT EXISTS event_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    option_id UUID NOT NULL REFERENCES event_options(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Payment
    amount_cents INTEGER NOT NULL,
    currency VARCHAR(3) DEFAULT 'EUR' NOT NULL,
    asd_amount_cents INTEGER NOT NULL,
    platform_amount_cents INTEGER NOT NULL,

    -- Stripe
    stripe_payment_intent_id VARCHAR(255) UNIQUE,
    stripe_transfer_id VARCHAR(255),

    -- Status
    status event_subscription_status DEFAULT 'pending' NOT NULL,

    -- Bundle
    bundle_course_granted BOOLEAN DEFAULT FALSE NOT NULL,
    bundle_course_granted_at TIMESTAMP,

    -- Participant Info
    participant_name VARCHAR(255),
    participant_email VARCHAR(255),
    participant_phone VARCHAR(50),
    dietary_requirements TEXT,
    notes TEXT,

    -- Cancellation
    cancelled_at TIMESTAMP,
    cancelled_by UUID REFERENCES users(id) ON DELETE SET NULL,
    cancellation_reason TEXT,

    -- Refund
    refunded_at TIMESTAMP,
    refund_amount_cents INTEGER,
    stripe_refund_id VARCHAR(255),

    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    confirmed_at TIMESTAMP,

    -- Unique constraint: one subscription per user per event
    CONSTRAINT uq_user_event_subscription UNIQUE (event_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_subs_event_status ON event_subscriptions(event_id, status);
CREATE INDEX IF NOT EXISTS idx_subs_user_status ON event_subscriptions(user_id, status);
CREATE INDEX IF NOT EXISTS idx_subs_payment ON event_subscriptions(stripe_payment_intent_id);

-- ============================================================
-- TABLE: event_waiting_list
-- ============================================================
CREATE TABLE IF NOT EXISTS event_waiting_list (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Preferred Option
    preferred_option_id UUID REFERENCES event_options(id) ON DELETE SET NULL,

    -- Notification
    notified_at TIMESTAMP,
    notification_count INTEGER DEFAULT 0 NOT NULL,

    -- Status
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    converted_to_subscription BOOLEAN DEFAULT FALSE NOT NULL,
    converted_at TIMESTAMP,

    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

    -- Unique constraint: one waiting list entry per user per event
    CONSTRAINT uq_user_event_waiting UNIQUE (event_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_waiting_list_event ON event_waiting_list(event_id, is_active);
CREATE INDEX IF NOT EXISTS idx_waiting_list_user ON event_waiting_list(user_id, is_active);

-- ============================================================
-- TABLE: asd_refund_requests
-- ============================================================
CREATE TABLE IF NOT EXISTS asd_refund_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID NOT NULL REFERENCES event_subscriptions(id) ON DELETE CASCADE,
    asd_id UUID NOT NULL REFERENCES asd_partners(id) ON DELETE CASCADE,

    -- Request
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT NOT NULL,
    requested_amount_cents INTEGER,

    -- Status
    status event_refund_status DEFAULT 'pending' NOT NULL,

    -- Approval
    requires_approval BOOLEAN NOT NULL,
    approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMP,
    rejection_reason TEXT,

    -- Processing
    processed_at TIMESTAMP,
    processed_amount_cents INTEGER,
    stripe_refund_id VARCHAR(255),
    processing_notes TEXT,

    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refund_requests_asd_status ON asd_refund_requests(asd_id, status);
CREATE INDEX IF NOT EXISTS idx_refund_requests_pending ON asd_refund_requests(status, requires_approval);
CREATE INDEX IF NOT EXISTS idx_refund_requests_subscription ON asd_refund_requests(subscription_id);

-- ============================================================
-- TABLE: platform_alert_config
-- ============================================================
CREATE TABLE IF NOT EXISTS platform_alert_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_type event_alert_type UNIQUE NOT NULL,

    -- Config
    enabled BOOLEAN DEFAULT TRUE NOT NULL,
    days_before INTEGER[],

    -- Channels
    email_enabled BOOLEAN DEFAULT TRUE NOT NULL,
    push_enabled BOOLEAN DEFAULT TRUE NOT NULL,
    dashboard_enabled BOOLEAN DEFAULT TRUE NOT NULL,
    sms_enabled BOOLEAN DEFAULT FALSE NOT NULL,

    -- Templates
    email_template_id VARCHAR(100),
    push_template TEXT,

    -- Audit
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_config_type ON platform_alert_config(alert_type);

-- ============================================================
-- TABLE: event_notifications
-- ============================================================
CREATE TABLE IF NOT EXISTS event_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,

    -- Alert Type
    alert_type event_alert_type NOT NULL,

    -- Schedule
    scheduled_for TIMESTAMP NOT NULL,

    -- Recipients
    recipient_type VARCHAR(50) NOT NULL,
    recipient_user_id UUID REFERENCES users(id) ON DELETE CASCADE,

    -- Channels
    channels VARCHAR(50)[] NOT NULL,

    -- Content
    subject VARCHAR(255),
    body TEXT,
    data JSONB,

    -- Status
    sent BOOLEAN DEFAULT FALSE NOT NULL,
    sent_at TIMESTAMP,
    send_attempts INTEGER DEFAULT 0 NOT NULL,
    last_error TEXT,

    -- Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_scheduled ON event_notifications(scheduled_for, sent);
CREATE INDEX IF NOT EXISTS idx_notifications_event_type ON event_notifications(event_id, alert_type);

-- ============================================================
-- SEED: Default Platform Alert Config
-- ============================================================
INSERT INTO platform_alert_config (alert_type, enabled, days_before, email_enabled, push_enabled, dashboard_enabled)
VALUES
    ('event_reminder', TRUE, ARRAY[7, 3, 1], TRUE, TRUE, TRUE),
    ('presale_start', TRUE, ARRAY[1], TRUE, TRUE, TRUE),
    ('sale_start', TRUE, ARRAY[1], TRUE, TRUE, TRUE),
    ('low_capacity', TRUE, NULL, TRUE, TRUE, TRUE),
    ('threshold_warning', TRUE, ARRAY[14, 7, 3], TRUE, FALSE, TRUE),
    ('waitlist_spot', TRUE, NULL, TRUE, TRUE, TRUE),
    ('refund_request', TRUE, NULL, TRUE, TRUE, TRUE),
    ('event_cancelled', TRUE, NULL, TRUE, TRUE, TRUE)
ON CONFLICT (alert_type) DO NOTHING;

-- ============================================================
-- COMMENTS
-- ============================================================
COMMENT ON TABLE asd_partners IS 'ASD partner con Stripe Connect per split payment';
COMMENT ON TABLE events IS 'Eventi/stage gestiti da ASD con presale e bundle';
COMMENT ON TABLE event_options IS 'Opzioni aggiuntive evento (pranzo, tshirt, etc.)';
COMMENT ON TABLE event_subscriptions IS 'Iscrizioni utenti con tracking pagamento split';
COMMENT ON TABLE event_waiting_list IS 'Waiting list con strategy notify-all-first-pays';
COMMENT ON TABLE asd_refund_requests IS 'Richieste rimborso con workflow approvazione';
COMMENT ON TABLE platform_alert_config IS 'Configurazione alert a livello piattaforma';
COMMENT ON TABLE event_notifications IS 'Notifiche schedulate e inviate';
"""


def run_migration():
    print("=" * 60)
    print("Running migration: create_events_tables")
    print("=" * 60)

    try:
        with engine.connect() as conn:
            # Execute migration
            conn.execute(text(MIGRATION_SQL))
            conn.commit()
            print("[OK] Migration completed successfully!")

            # Verify tables created
            result = conn.execute(text("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name IN (
                    'asd_partners',
                    'events',
                    'event_options',
                    'event_subscriptions',
                    'event_waiting_list',
                    'asd_refund_requests',
                    'platform_alert_config',
                    'event_notifications'
                )
                ORDER BY table_name
            """))

            print("\nEvents module tables created:")
            print("-" * 40)
            for row in result:
                print(f"  [OK] {row[0]}")

            # Count platform_alert_config rows
            result = conn.execute(text("""
                SELECT COUNT(*) FROM platform_alert_config
            """))
            count = result.scalar()
            print(f"\n  [OK] platform_alert_config seeded with {count} alert types")

    except Exception as e:
        print(f"[ERROR] Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    run_migration()
