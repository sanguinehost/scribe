-- Set trial end to 10 minutes from now for testing trial expiration behavior
-- Run this script to test automatic transition from cancelled trial to free tier

-- First, check current state
SELECT
    id,
    user_id,
    status,
    plan_type,
    current_period_end,
    trial_end,
    NOW() as current_time,
    EXTRACT(EPOCH FROM (trial_end - NOW())) / 60 as minutes_until_trial_end
FROM subscriptions
WHERE user_id = 1;

-- Update trial_end and current_period_end to 10 minutes from now
UPDATE subscriptions
SET
    trial_end = NOW() + INTERVAL '10 minutes',
    current_period_end = NOW() + INTERVAL '10 minutes',
    updated_at = NOW()
WHERE user_id = 1 AND status = 'canceled';

-- Verify the update
SELECT
    id,
    user_id,
    status,
    plan_type,
    current_period_end,
    trial_end,
    NOW() as current_time,
    EXTRACT(EPOCH FROM (trial_end - NOW())) / 60 as minutes_until_trial_end,
    'UPDATED FOR TESTING' as note
FROM subscriptions
WHERE user_id = 1;
