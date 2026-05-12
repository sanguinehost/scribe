-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-20T19:54:56.898358
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Enhanced Paddle Subscription Recovery Migration
-- This migration provides SQL-based recovery for missing paddle_subscription_ids
-- and prepares the system for runtime recovery through the sync mechanism

-- First, let's create a function to log recovery attempts
-- CREATE OR REPLACE FUNCTION log_paddle_recovery(
--     p_subscription_id TEXT,
--     p_paddle_customer_id... -- Removed: SQLite does not support PL/pgSQL

-- Create a temporary table to track recovery progress
CREATE TEMP TABLE paddle_recovery_log (
    subscription_id TEXT,
    paddle_customer_id VARCHAR,
    recovery_method VARCHAR,
    result VARCHAR,
    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Step 1: Mark subscriptions that need recovery
-- These have paddle_customer_id but missing paddle_subscription_id
UPDATE subscriptions
SET paddle_sync_attempted = FALSE
WHERE paddle_customer_id IS NOT NULL
  AND paddle_subscription_id IS NULL
  AND NOT paddle_sync_attempted;

-- Log how many subscriptions need recovery
-- DO $$ -- SQLite Note: SQLite doesn't support DO blocks or information_schema for idempotent migrations
-- DECLARE
--     recovery_count INTEGER;
-- BEGIN
--     SELECT COUNT(*) INTO recovery_count
--     FROM subscriptions
--     WHERE paddle_customer_id IS NOT NULL
--       AND paddle_subscription_id IS NULL;
--
--     RAISE NOTICE 'PADDLE_RECOVERY: Found % subscriptions requiring paddle_subscription_id recovery', recovery_count;
--
    -- Insert summary into recovery log
--     INSERT INTO paddle_recovery_log (subscription_id, paddle_customer_id, recovery_method, result)
--     VALUES (
--         '00000000-0000-0000-0000-000000000000',
--         'SYSTEM',
--         'MIGRATION_SUMMARY',
--         format('Found %s subscriptions needing recovery', recovery_count)
--     );
-- END $$;

-- Step 2: Handle known patterns where we can infer paddle_subscription_id
-- For example, if there are patterns in existing data, we could add logic here
-- Currently, we'll just mark these for runtime recovery

-- Step 3: Create indexes to optimize the runtime recovery process
-- Index for finding subscriptions that need recovery
CREATE INDEX IF NOT EXISTS idx_subscriptions_needs_paddle_recovery
ON subscriptions (paddle_customer_id, paddle_sync_attempted, created_at)
WHERE paddle_subscription_id IS NULL AND paddle_customer_id IS NOT NULL;

-- Index for checking existing paddle_subscription_ids to avoid duplicates
CREATE INDEX IF NOT EXISTS idx_subscriptions_paddle_id_lookup
ON subscriptions (paddle_subscription_id)
WHERE paddle_subscription_id IS NOT NULL;

-- Step 4: Add comments for documentation
-- COMMENT ON INDEX idx_subscriptions_needs_paddle_recovery IS
-- SQLite Note: SQLite doesn't support COMMENT ON syntax, comments are stored as schema documentation
-- 'Optimizes queries for finding subscriptions that need paddle_subscription_id recovery during runtime sync';

-- COMMENT ON INDEX idx_subscriptions_paddle_id_lookup IS
-- SQLite Note: SQLite doesn't support COMMENT ON syntax, comments are stored as schema documentation
-- 'Optimizes lookups when checking for existing paddle_subscription_ids during recovery';

-- Step 5: Update statistics for better query planning
ANALYZE subscriptions;

-- Step 6: Final reporting
-- DO $$ -- SQLite Note: SQLite doesn't support DO blocks or information_schema for idempotent migrations
-- DECLARE
--     total_subscriptions INTEGER;
--     with_paddle_customer INTEGER;
--     with_paddle_subscription INTEGER;
--     needing_recovery INTEGER;
-- BEGIN
    -- Get statistics
--     SELECT COUNT(*) INTO total_subscriptions FROM subscriptions;
--
--     SELECT COUNT(*) INTO with_paddle_customer
--     FROM subscriptions WHERE paddle_customer_id IS NOT NULL;
--
--     SELECT COUNT(*) INTO with_paddle_subscription
--     FROM subscriptions WHERE paddle_subscription_id IS NOT NULL;
--
--     SELECT COUNT(*) INTO needing_recovery
--     FROM subscriptions
--     WHERE paddle_customer_id IS NOT NULL AND paddle_subscription_id IS NULL;
--
    -- Log final statistics
--     RAISE NOTICE 'PADDLE_RECOVERY: MIGRATION COMPLETE';
--     RAISE NOTICE 'PADDLE_RECOVERY: Total subscriptions: %', total_subscriptions;
--     RAISE NOTICE 'PADDLE_RECOVERY: With paddle_customer_id: %', with_paddle_customer;
--     RAISE NOTICE 'PADDLE_RECOVERY: With paddle_subscription_id: %', with_paddle_subscription;
--     RAISE NOTICE 'PADDLE_RECOVERY: Needing recovery: %', needing_recovery;
--     RAISE NOTICE 'PADDLE_RECOVERY: Runtime recovery will handle missing paddle_subscription_ids automatically';
--
    -- Final log entry
--     INSERT INTO paddle_recovery_log (subscription_id, paddle_customer_id, recovery_method, result)
--     VALUES (
--         '00000000-0000-0000-0000-000000000000',
--         'SYSTEM',
--         'MIGRATION_COMPLETE',
--         format('Recovery setup complete. %s subscriptions marked for runtime recovery', needing_recovery)
--     );
-- END $$;

-- Clean up the temporary function (keeping indexes for performance)
-- DROP FUNCTION log_paddle_recovery(TEXT, VARCHAR, VARCHAR, VARCHAR); -- SQLite Note: Function was never created
