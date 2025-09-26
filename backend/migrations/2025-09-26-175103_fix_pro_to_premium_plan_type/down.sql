-- Rollback: Convert 'premium' plan_type back to 'pro' if needed
-- This reverses the fix applied in up.sql

-- Restore the original 'pro' plan in plan_features table
-- (Only if we're rolling back and there's no existing 'pro' plan)
INSERT INTO plan_features (plan_type, monthly_token_limit, characters_limit, lorebooks_limit, price_cents, paddle_price_id, display_name, description, features, created_at, updated_at)
SELECT
    'pro',                          -- plan_type
    monthly_token_limit,            -- Keep same limits
    characters_limit,               -- Keep same limits
    lorebooks_limit,                -- Keep same limits
    price_cents,                    -- Keep same price
    paddle_price_id,                -- Keep same price ID
    'Pro',                          -- Original display_name
    'For serious character AI enthusiasts and creators', -- Original description
    features,                       -- Keep same features
    created_at,                     -- Keep original created_at
    NOW()                           -- Update the updated_at timestamp
FROM plan_features
WHERE plan_type = 'premium'
AND NOT EXISTS (SELECT 1 FROM plan_features WHERE plan_type = 'pro');

-- Revert all subscriptions that have plan_type 'premium' back to 'pro'
-- (This should only affect subscriptions that were changed by the up migration)
UPDATE subscriptions
SET plan_type = 'pro'
WHERE plan_type = 'premium';

-- Remove the premium plan if it was created during the migration
-- (Only if we have both 'pro' and 'premium' plans)
DELETE FROM plan_features
WHERE plan_type = 'premium'
AND EXISTS (SELECT 1 FROM plan_features WHERE plan_type = 'pro');
