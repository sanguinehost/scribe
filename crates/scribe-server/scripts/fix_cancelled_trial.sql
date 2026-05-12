-- Fix cancelled trial subscription dates
-- This script finds cancelled subscriptions with future billing dates and corrects them

-- First, let's see what we're working with
SELECT
    id,
    user_id,
    paddle_subscription_id,
    status,
    plan_type,
    current_period_end::date as billing_date,
    trial_end::date as trial_date,
    created_at::date as created_date,
    (current_period_end > NOW() + INTERVAL '20 days') as has_future_billing
FROM subscriptions
WHERE status = 'canceled'
ORDER BY created_at DESC;

-- Update cancelled trial subscriptions with correct dates
-- Set trial_end to 7 days after creation (typical trial period)
-- Set current_period_end to match trial_end for cancelled trials
UPDATE subscriptions
SET
    trial_end = created_at + INTERVAL '7 days',
    current_period_end = created_at + INTERVAL '7 days',
    updated_at = NOW()
WHERE
    status = 'canceled'
    AND current_period_end > NOW() + INTERVAL '20 days'
    AND trial_end IS NULL;

-- Show the results after the fix
SELECT
    id,
    user_id,
    paddle_subscription_id,
    status,
    plan_type,
    current_period_end::date as billing_date,
    trial_end::date as trial_date,
    created_at::date as created_date,
    'FIXED' as note
FROM subscriptions
WHERE status = 'canceled'
ORDER BY created_at DESC;
