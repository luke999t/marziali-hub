"""
FIX_2025_01_21: Add missing columns for model-DB sync.
Run with: python migrations/run_007_migration.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine

def run_migration():
    print("=" * 50)
    print("Migration: add_missing_columns_2025_01_21")
    print("=" * 50)

    steps = [
        ("Create fiscalreceipttype enum",
         "CREATE TYPE fiscalreceipttype AS ENUM ('contributo_spontaneo', 'donazione_liberale')"),

        ("Add fiscal_receipt_type to donations",
         "ALTER TABLE donations ADD COLUMN IF NOT EXISTS fiscal_receipt_type fiscalreceipttype"),

        ("Create withdrawalstatus enum",
         "CREATE TYPE withdrawalstatus AS ENUM ('pending', 'approved', 'processing', 'completed', 'rejected')"),

        ("Create payoutmethod enum",
         "CREATE TYPE payoutmethod AS ENUM ('sepa', 'paypal', 'stripe', 'numia')"),

        ("Add status to withdrawal_requests",
         "ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS status withdrawalstatus DEFAULT 'pending'"),

        ("Add payout_method to withdrawal_requests",
         "ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS payout_method payoutmethod"),
    ]

    for name, sql in steps:
        print(f"\n{name}...")
        try:
            with engine.connect() as conn:
                conn.execute(text(sql))
                conn.commit()
                print(f"  [OK] Done")
        except Exception as e:
            err = str(e).lower()
            if 'already exists' in err or 'duplicate' in err:
                print(f"  [OK] Already exists")
            else:
                print(f"  [WARN] {e}")

    # Verify
    print("\n" + "=" * 50)
    print("Verifying columns...")
    print("=" * 50)

    inspector = inspect(engine)
    donations_cols = [c['name'] for c in inspector.get_columns('donations')]
    withdrawal_cols = [c['name'] for c in inspector.get_columns('withdrawal_requests')]

    results = [
        ("donations.fiscal_receipt_type", 'fiscal_receipt_type' in donations_cols),
        ("withdrawal_requests.status", 'status' in withdrawal_cols),
        ("withdrawal_requests.payout_method", 'payout_method' in withdrawal_cols),
    ]

    all_ok = True
    for col, exists in results:
        status = "OK" if exists else "MISSING"
        print(f"  {col}: {status}")
        if not exists:
            all_ok = False

    if all_ok:
        print("\n[SUCCESS] All columns added!")
    else:
        print("\n[WARNING] Some columns still missing")

if __name__ == "__main__":
    run_migration()
