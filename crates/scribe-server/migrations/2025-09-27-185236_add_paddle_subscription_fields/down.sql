-- Rollback Paddle subscription fields migration

-- Drop indexes first
DROP INDEX IF EXISTS idx_subscriptions_next_billed_at;
DROP INDEX IF EXISTS idx_subscriptions_canceled_at;
DROP INDEX IF EXISTS idx_subscriptions_trial_ends_at;

-- Drop the new columns
ALTER TABLE subscriptions DROP COLUMN IF EXISTS first_billed_at;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS next_billed_at;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS canceled_at;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS paused_at;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS trial_starts_at;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS trial_ends_at;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS scheduled_change;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS management_urls;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS discount;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS collection_mode;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS billing_details;
