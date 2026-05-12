-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-20T19:54:56.897256
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Fix incorrect 'pro' plan_type to 'premium' for existing subscriptions
-- This addresses the issue where users who purchased premium subscriptions
-- had their plan_type incorrectly set to 'pro' instead of 'premium'

-- Update all subscriptions that have plan_type 'pro' to 'premium'
-- since 'pro' was the incorrect mapping and should be 'premium'
UPDATE subscriptions
SET plan_type = 'premium'
WHERE plan_type = 'pro';

-- Update the 'pro' plan in plan_features to have 'premium' plan_type
-- or alternatively, we could delete it since we now use 'basic' and 'premium'
-- For safety, we'll update it to match premium pricing and features
UPDATE plan_features
SET
    plan_type = 'premium',
    display_name = 'Premium',
    description = 'Professional roleplay & storytelling platform',
    monthly_token_limit = 5000000,  -- Match premium tier
    characters_limit = 25,          -- Match premium tier
    lorebooks_limit = 10,           -- Match premium tier
    price_cents = 2500,             -- $25.00 monthly price for premium
    features = '{"daily_messages": 200, "models": ["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.5-pro"], "priority_support": true}'::TEXT,
    updated_at = NOW()
WHERE plan_type = 'pro'
AND NOT EXISTS (SELECT 1 FROM plan_features WHERE plan_type = 'premium');

-- If premium plan already exists, just delete the 'pro' plan
DELETE FROM plan_features
WHERE plan_type = 'pro'
AND EXISTS (SELECT 1 FROM plan_features WHERE plan_type = 'premium');
