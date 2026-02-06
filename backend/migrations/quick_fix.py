#!/usr/bin/env python3
"""Quick migration fix - run standalone"""
import psycopg2

conn = psycopg2.connect(
    host='localhost',
    database='martial_arts_db',
    user='martial_user',
    password='martial_pass'
)
conn.autocommit = True
cur = conn.cursor()

print("Adding missing columns...")

sqls = [
    "ALTER TABLE donations ADD COLUMN IF NOT EXISTS fiscal_receipt_type VARCHAR(50)",
    "ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'pending'",
    "ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS payout_method VARCHAR(20)",
    # FIX_2025_01_21: Add missing columns for 5 unit test errors
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_type VARCHAR(50)",
    "ALTER TABLE correction_requests ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'pending'",
    "ALTER TABLE live_events ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'scheduled'",
]

for sql in sqls:
    try:
        cur.execute(sql)
        print(f"  OK: {sql[:60]}...")
    except Exception as e:
        print(f"  Error: {e}")

print("\nVerifying...")
cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='donations' AND column_name='fiscal_receipt_type'")
print(f"  donations.fiscal_receipt_type: {'OK' if cur.fetchone() else 'MISSING'}")

cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='withdrawal_requests' AND column_name='status'")
print(f"  withdrawal_requests.status: {'OK' if cur.fetchone() else 'MISSING'}")

cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='withdrawal_requests' AND column_name='payout_method'")
print(f"  withdrawal_requests.payout_method: {'OK' if cur.fetchone() else 'MISSING'}")

# FIX_2025_01_21: Verify new columns
cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='messages' AND column_name='attachment_type'")
print(f"  messages.attachment_type: {'OK' if cur.fetchone() else 'MISSING'}")

cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='correction_requests' AND column_name='status'")
print(f"  correction_requests.status: {'OK' if cur.fetchone() else 'MISSING'}")

cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='live_events' AND column_name='status'")
print(f"  live_events.status: {'OK' if cur.fetchone() else 'MISSING'}")

cur.close()
conn.close()
print("\nDone!")
