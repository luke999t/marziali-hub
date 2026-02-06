-- FIX_2025_01_21: Add missing columns for model-DB sync
-- Run with: psql -d martial_arts_db -f migrations/007_add_missing_columns.sql

-- 1. Create FiscalReceiptType enum
DO $$ BEGIN
    CREATE TYPE fiscalreceipttype AS ENUM ('contributo_spontaneo', 'donazione_liberale');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 2. Add fiscal_receipt_type to donations
ALTER TABLE donations
    ADD COLUMN IF NOT EXISTS fiscal_receipt_type fiscalreceipttype;

-- 3. Create WithdrawalStatus enum
DO $$ BEGIN
    CREATE TYPE withdrawalstatus AS ENUM ('pending', 'approved', 'processing', 'completed', 'rejected');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 4. Create PayoutMethod enum
DO $$ BEGIN
    CREATE TYPE payoutmethod AS ENUM ('sepa', 'paypal', 'stripe', 'numia');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 5. Add status and payout_method to withdrawal_requests
ALTER TABLE withdrawal_requests
    ADD COLUMN IF NOT EXISTS status withdrawalstatus DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS payout_method payoutmethod;

-- 6. Create indexes
CREATE INDEX IF NOT EXISTS idx_donation_fiscal ON donations(fiscal_receipt_type, created_at);
CREATE INDEX IF NOT EXISTS idx_withdrawal_status ON withdrawal_requests(status);

-- Verify
SELECT 'donations.fiscal_receipt_type' as column_added,
       EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='donations' AND column_name='fiscal_receipt_type') as exists;
SELECT 'withdrawal_requests.status' as column_added,
       EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='withdrawal_requests' AND column_name='status') as exists;
SELECT 'withdrawal_requests.payout_method' as column_added,
       EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='withdrawal_requests' AND column_name='payout_method') as exists;
