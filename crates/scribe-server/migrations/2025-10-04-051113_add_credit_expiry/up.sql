-- Add expires_at column to credit_transactions table for credit expiry functionality
-- This enables tracking when credits expire based on credit_expiry_days config

ALTER TABLE credit_transactions
ADD COLUMN expires_at TIMESTAMPTZ;

-- Backfill existing credit transactions with expiry date
-- Uses created_at + 365 days (default credit_expiry_days from config)
UPDATE credit_transactions
SET expires_at = created_at + INTERVAL '365 days'
WHERE expires_at IS NULL;

-- Index for cleanup queries (finding expired credits by date)
CREATE INDEX idx_credit_transactions_expires_at
ON credit_transactions(expires_at)
WHERE expires_at IS NOT NULL;

-- Composite index for available balance queries (user_id + expiry check)
-- Optimizes: SELECT SUM(amount) WHERE user_id = ? AND (expires_at IS NULL OR expires_at > NOW())
CREATE INDEX idx_credit_transactions_user_expiry
ON credit_transactions(user_id, expires_at);
