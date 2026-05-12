-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-20T19:54:56.900238
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add new Paddle subscription fields for complete lifecycle tracking
-- These fields come directly from Paddle's API and provide granular subscription control

-- Billing timeline fields
ALTER TABLE subscriptions ADD COLUMN first_billed_at DATETIME;
ALTER TABLE subscriptions ADD COLUMN next_billed_at DATETIME;
ALTER TABLE subscriptions ADD COLUMN canceled_at DATETIME;
ALTER TABLE subscriptions ADD COLUMN paused_at DATETIME;

-- Trial period tracking
ALTER TABLE subscriptions ADD COLUMN trial_starts_at DATETIME;
ALTER TABLE subscriptions ADD COLUMN trial_ends_at DATETIME;

-- Scheduled changes (JSON field for flexibility)
ALTER TABLE subscriptions ADD COLUMN scheduled_change TEXT;

-- Management URLs (JSON field for flexibility)
ALTER TABLE subscriptions ADD COLUMN management_urls TEXT;

-- Discount information (JSON field for flexibility)
ALTER TABLE subscriptions ADD COLUMN discount TEXT;

-- Collection mode (manual, automatic)
ALTER TABLE subscriptions ADD COLUMN collection_mode TEXT;

-- Additional billing details (JSON field for flexibility)
ALTER TABLE subscriptions ADD COLUMN billing_details TEXT;

-- Add indexes for commonly queried fields
CREATE INDEX idx_subscriptions_next_billed_at ON subscriptions(next_billed_at) WHERE next_billed_at IS NOT NULL;
CREATE INDEX idx_subscriptions_canceled_at ON subscriptions(canceled_at) WHERE canceled_at IS NOT NULL;
CREATE INDEX idx_subscriptions_trial_ends_at ON subscriptions(trial_ends_at) WHERE trial_ends_at IS NOT NULL;

-- Add comment explaining the new fields
COMMENT ON COLUMN subscriptions.first_billed_at IS 'When the subscription was first billed (trial conversion date)';
COMMENT ON COLUMN subscriptions.next_billed_at IS 'When the subscription will next be billed';
COMMENT ON COLUMN subscriptions.canceled_at IS 'When cancellation was requested (different from status change)';
COMMENT ON COLUMN subscriptions.paused_at IS 'When the subscription was paused';
COMMENT ON COLUMN subscriptions.trial_starts_at IS 'When the trial period started';
COMMENT ON COLUMN subscriptions.trial_ends_at IS 'When the trial period ends/ended';
COMMENT ON COLUMN subscriptions.scheduled_change IS 'JSON: Upcoming scheduled changes (pause, cancel, etc.)';
COMMENT ON COLUMN subscriptions.management_urls IS 'JSON: Paddle customer portal URLs';
COMMENT ON COLUMN subscriptions.discount IS 'JSON: Applied discount information';
COMMENT ON COLUMN subscriptions.collection_mode IS 'How payments are collected (automatic, manual)';
COMMENT ON COLUMN subscriptions.billing_details IS 'JSON: Additional billing configuration';
