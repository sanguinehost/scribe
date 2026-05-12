-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.895788
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Revert credit system changes

-- Drop triggers
DROP TRIGGER IF EXISTS update_credit_packages_updated_at ON credit_packages;
DROP TRIGGER IF EXISTS update_daily_usage_tracking_updated_at ON daily_usage_tracking;
DROP TRIGGER IF EXISTS update_user_credits_updated_at ON user_credits;

-- Drop function if no other triggers use it
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes
DROP INDEX IF EXISTS idx_credit_packages_active;
DROP INDEX IF EXISTS idx_daily_usage_soft_limit;
DROP INDEX IF EXISTS idx_daily_usage_date;
DROP INDEX IF EXISTS idx_daily_usage_user_date;
DROP INDEX IF EXISTS idx_credit_transactions_reference;
DROP INDEX IF EXISTS idx_credit_transactions_type;
DROP INDEX IF EXISTS idx_credit_transactions_created_at;
DROP INDEX IF EXISTS idx_credit_transactions_user_id;

-- Remove columns from existing tables
ALTER TABLE users
DROP COLUMN IF EXISTS last_daily_usage_reset,
DROP COLUMN IF EXISTS cached_subscription_tier,
DROP COLUMN IF EXISTS cached_credit_balance;

ALTER TABLE subscriptions
DROP COLUMN IF EXISTS last_credit_grant,
DROP COLUMN IF EXISTS soft_limit_override,
DROP COLUMN IF EXISTS credits_allocated_this_period;

-- Drop tables
DROP TABLE IF EXISTS credit_packages;
DROP TABLE IF EXISTS daily_usage_tracking;
DROP TABLE IF EXISTS credit_transactions;
DROP TABLE IF EXISTS user_credits;
