"""
Migration script to add missing columns to users table.
Run: python migrations/run_migration.py
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from core.database import engine

MIGRATION_SQL = """
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
"""


def run_migration():
    print("=" * 50)
    print("Running migration: add_user_columns")
    print("=" * 50)

    try:
        with engine.connect() as conn:
            # Execute migration
            conn.execute(text(MIGRATION_SQL))
            conn.commit()
            print("[OK] Migration completed successfully!")

            # Verify columns
            result = conn.execute(text("""
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_name = 'users'
                ORDER BY ordinal_position
            """))

            print("\nCurrent users table columns:")
            print("-" * 40)
            for row in result:
                print(f"  {row[0]}: {row[1]}")

    except Exception as e:
        print(f"[ERROR] Migration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_migration()
