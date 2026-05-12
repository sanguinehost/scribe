-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-20T19:54:56.896121
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add basic and premium plan types to plan_features table
-- These tiers match the subscription_tiers.json configuration

INSERT INTO plan_features (plan_type, display_name, description, monthly_token_limit, characters_limit, lorebooks_limit, price_cents, features, created_at, updated_at)
VALUES
-- Basic tier: $5/month, 100 daily messages, standard features
('basic',
 'Basic',                               -- display_name
 'Standard features for regular users', -- description
 1000000,                               -- monthly_token_limit (1M tokens)
 10,                                    -- characters_limit
 5,                                     -- lorebooks_limit
 500,                                   -- price_cents ($5.00)
 '{"daily_messages": 100, "models": ["gemini-2.5-flash", "gemini-2.5-flash-lite"], "priority_support": false}'::TEXT,
 NOW(),                                 -- created_at
 NOW()                                  -- updated_at
),
-- Premium tier: $20/month, 200 daily messages, all features
('premium',
 'Premium',                             -- display_name
 'Advanced features for power users',   -- description
 5000000,                               -- monthly_token_limit (5M tokens)
 25,                                    -- characters_limit
 10,                                    -- lorebooks_limit
 2000,                                  -- price_cents ($20.00)
 '{"daily_messages": 200, "models": ["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.5-pro"], "priority_support": true}'::TEXT,
 NOW(),                                 -- created_at
 NOW()                                  -- updated_at
)
ON CONFLICT (plan_type) DO NOTHING;
