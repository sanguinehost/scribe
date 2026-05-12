-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-20T19:54:56.903091
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add scheduled plan change tracking for downgrades
-- When a user downgrades their subscription, we schedule the change for the end
-- of their current billing period so they retain access to paid features until then

ALTER TABLE subscriptions ADD COLUMN scheduled_plan_change TEXT;
ALTER TABLE subscriptions ADD COLUMN scheduled_change_date DATETIME;
-- Index for efficient scheduler queries
-- Only index rows with pending changes to minimize index size
CREATE INDEX idx_subscriptions_scheduled_change
ON subscriptions(scheduled_plan_change, scheduled_change_date)
WHERE scheduled_plan_change IS NOT NULL;

-- Add documentation comments
-- COMMENT ON COLUMN subscriptions.scheduled_plan_change IS 'Pending plan change (e.g., from premium to basic) scheduled for future date. Used for downgrades to preserve access until period end.';
-- COMMENT ON COLUMN subscriptions.scheduled_change_date IS 'When scheduled_plan_change will be applied. Typically set to current_period_end for downgrades.';
