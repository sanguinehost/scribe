-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.898265
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Reverse the migration changes

-- Drop the index
DROP INDEX IF EXISTS idx_subscriptions_paddle_sync_recovery;

-- Remove the tracking column
ALTER TABLE subscriptions DROP COLUMN IF EXISTS paddle_sync_attempted;
