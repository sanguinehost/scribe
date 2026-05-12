-- This file should undo anything in `up.sql`
-- Revert enhanced subscription lifecycle fields

-- Remove the new subscription lifecycle fields
ALTER TABLE subscriptions DROP COLUMN IF EXISTS paddle_trial_end;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS cancellation_reason_nonce;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS cancellation_reason_encrypted;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS previous_subscription_id;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS grace_period_end;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS last_payment_date;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS trial_start_date;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS cancellation_date;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS has_ever_paid;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS first_payment_date;
