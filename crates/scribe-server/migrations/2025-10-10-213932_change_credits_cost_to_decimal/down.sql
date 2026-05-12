-- Revert credits_cost back to INTEGER
-- Note: This will cause data loss for fractional dollar amounts

ALTER TABLE chat_messages
ALTER COLUMN credits_cost TYPE INTEGER USING ROUND(credits_cost);

ALTER TABLE chat_sessions
ALTER COLUMN total_credits_used TYPE INTEGER USING ROUND(total_credits_used);
