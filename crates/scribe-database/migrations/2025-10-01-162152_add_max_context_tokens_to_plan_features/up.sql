-- Add max_context_tokens column to plan_features table
-- This enforces subscription tier limits on context window size

ALTER TABLE plan_features ADD COLUMN max_context_tokens INTEGER;

-- Set context limits for each tier:
-- Free: 64,000 tokens
-- Basic: 100,000 tokens (raised from previous limit)
-- Premium: 200,000 tokens (maximum reasonable context)

UPDATE plan_features SET max_context_tokens = 64000 WHERE plan_type = 'free';
UPDATE plan_features SET max_context_tokens = 100000 WHERE plan_type = 'basic';
UPDATE plan_features SET max_context_tokens = 200000 WHERE plan_type = 'premium';
