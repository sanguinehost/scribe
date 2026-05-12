-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-20T19:54:56.898028
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add a tracking column to identify which subscriptions need Paddle ID recovery
-- This migration prepares the database for a separate recovery process

-- Add tracking column for Paddle sync attempts
ALTER TABLE subscriptions ADD COLUMN paddle_sync_attempted BOOLEAN NOT NULL DEFAULT FALSE;

-- Add index for efficient querying during recovery
CREATE INDEX idx_subscriptions_paddle_sync_recovery
ON subscriptions (paddle_customer_id, paddle_subscription_id, paddle_sync_attempted)
WHERE paddle_subscription_id IS NULL AND paddle_customer_id IS NOT NULL;

-- Update the tracking column for subscriptions that already have paddle_subscription_id
UPDATE subscriptions
SET paddle_sync_attempted = TRUE
WHERE paddle_subscription_id IS NOT NULL;

-- Add comment explaining the purpose
COMMENT ON COLUMN subscriptions.paddle_sync_attempted IS 'Tracks whether recovery process attempted to fetch paddle_subscription_id from Paddle API';
