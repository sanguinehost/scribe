-- Add enhanced subscription lifecycle fields
-- Per SUBSCRIPTION_CREDIT_ARCHITECTURE.md

-- Add new subscription lifecycle tracking fields
ALTER TABLE subscriptions ADD COLUMN first_payment_date TIMESTAMPTZ;
ALTER TABLE subscriptions ADD COLUMN has_ever_paid BOOLEAN DEFAULT false;
ALTER TABLE subscriptions ADD COLUMN cancellation_date TIMESTAMPTZ;
ALTER TABLE subscriptions ADD COLUMN trial_start_date TIMESTAMPTZ;
ALTER TABLE subscriptions ADD COLUMN last_payment_date TIMESTAMPTZ;
ALTER TABLE subscriptions ADD COLUMN grace_period_end TIMESTAMPTZ;
ALTER TABLE subscriptions ADD COLUMN previous_subscription_id UUID REFERENCES subscriptions(id);
ALTER TABLE subscriptions ADD COLUMN cancellation_reason_encrypted BYTEA;
ALTER TABLE subscriptions ADD COLUMN cancellation_reason_nonce BYTEA;
ALTER TABLE subscriptions ADD COLUMN paddle_trial_end TIMESTAMPTZ;

-- Set has_ever_paid to true for existing active/cancelled subscriptions
-- (assumes any non-trial subscription has been paid)
UPDATE subscriptions
SET has_ever_paid = true
WHERE status IN ('active', 'cancelled', 'past_due') OR status = 'pending_cancellation';

-- Initialize trial_start_date for existing subscriptions based on created_at
UPDATE subscriptions
SET trial_start_date = created_at
WHERE trial_end IS NOT NULL AND trial_start_date IS NULL;

-- Initialize paddle_trial_end from existing trial_end field
UPDATE subscriptions
SET paddle_trial_end = trial_end
WHERE trial_end IS NOT NULL;
