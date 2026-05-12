-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.903344
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Rollback scheduled plan change tracking

DROP INDEX IF EXISTS idx_subscriptions_scheduled_change;

ALTER TABLE subscriptions
DROP COLUMN IF EXISTS scheduled_plan_change,
DROP COLUMN IF EXISTS scheduled_change_date;
