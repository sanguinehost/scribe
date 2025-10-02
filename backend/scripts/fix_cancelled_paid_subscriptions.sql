-- Fix cancelled paid subscriptions that have trial_end persisting from their trial period
-- This script identifies subscriptions that:
-- 1. Have status 'canceled'
-- 2. Have a trial_end date
-- 3. Have a current_period_end date that is AFTER trial_end (indicating they converted to paid)
-- 4. Don't have has_ever_paid set to true yet

-- First, show the subscriptions that will be updated
SELECT
    id,
    user_id,
    plan_type,
    status,
    trial_end,
    current_period_end,
    has_ever_paid,
    first_payment_date,
    created_at,
    updated_at
FROM subscriptions
WHERE status = 'canceled'
  AND trial_end IS NOT NULL
  AND current_period_end > trial_end
  AND (has_ever_paid IS NULL OR has_ever_paid = false);

-- Update these subscriptions to mark them as having paid
-- Set has_ever_paid = true and first_payment_date to current_period_start
UPDATE subscriptions
SET
    has_ever_paid = true,
    first_payment_date = current_period_start,
    updated_at = NOW()
WHERE status = 'canceled'
  AND trial_end IS NOT NULL
  AND current_period_end > trial_end
  AND (has_ever_paid IS NULL OR has_ever_paid = false);

-- Verify the updates
SELECT
    id,
    user_id,
    plan_type,
    status,
    trial_end,
    current_period_end,
    has_ever_paid,
    first_payment_date,
    created_at,
    updated_at
FROM subscriptions
WHERE status = 'canceled'
  AND trial_end IS NOT NULL
  AND current_period_end > trial_end;
