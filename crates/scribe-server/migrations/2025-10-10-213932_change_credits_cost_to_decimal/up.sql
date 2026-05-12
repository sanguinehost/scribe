-- Change credits_cost from INTEGER to DECIMAL to store exact dollar amounts
-- This allows storing fractional costs without rounding errors

-- chat_messages.credits_cost: stores base Google API cost in dollars
ALTER TABLE chat_messages
ALTER COLUMN credits_cost TYPE DECIMAL(10, 6);

-- chat_sessions.total_credits_used: stores cumulative base API cost in dollars (local) or credits (production)
ALTER TABLE chat_sessions
ALTER COLUMN total_credits_used TYPE DECIMAL(10, 6);
