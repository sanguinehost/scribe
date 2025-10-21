-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-20T19:54:56.897049
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add yearly price ID column to plan_features table
ALTER TABLE plan_features
ADD COLUMN paddle_price_id_yearly TEXT;

-- Update existing rows with yearly price IDs from environment variables
UPDATE plan_features
SET paddle_price_id_yearly = CASE
    WHEN plan_type = 'basic' THEN 'pri_01k5ejs7h9zmw4d888r3pjjqna'
    WHEN plan_type = 'premium' THEN 'pri_01k5ejva0cwqzbtgzd2c9qk0d4'
    ELSE NULL
-- END;
