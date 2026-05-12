-- Add proper cost tracking fields to chat_messages
-- This migration separates concerns: actual API cost, modified cost with markup, and credit consumption

-- Add actual_cost: raw Google API cost in dollars (ALWAYS calculated, no feature flags)
ALTER TABLE chat_messages
ADD COLUMN actual_cost DECIMAL(10, 6) NOT NULL DEFAULT 0;

COMMENT ON COLUMN chat_messages.actual_cost IS 'Raw Google API cost in dollars (always calculated regardless of payment feature)';

-- Add modified_cost: actual_cost with markup applied (populated if payment feature enabled)
ALTER TABLE chat_messages
ADD COLUMN modified_cost DECIMAL(10, 6) NOT NULL DEFAULT 0;

COMMENT ON COLUMN chat_messages.modified_cost IS 'Cost with markup applied (e.g., 20% over actual_cost) when payment feature is enabled';

-- Add credit_cost: actual credits consumed (ONLY when credits are used)
ALTER TABLE chat_messages
ADD COLUMN credit_cost INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN chat_messages.credit_cost IS 'Credits consumed (only populated when user actually uses credits - baseline exceeded or premium model)';

-- Add actual_charge: actual dollar amount charged to user
ALTER TABLE chat_messages
ADD COLUMN actual_charge DECIMAL(10, 6) NOT NULL DEFAULT 0;

COMMENT ON COLUMN chat_messages.actual_charge IS 'Actual dollar amount charged to user (if any)';

-- Backfill actual_cost from existing credits_cost (which was misused to store dollar amounts)
UPDATE chat_messages
SET actual_cost = credits_cost
WHERE credits_cost > 0;

-- Add indexes for cost-based queries
CREATE INDEX idx_chat_messages_actual_cost ON chat_messages(session_id, actual_cost) WHERE actual_cost > 0;
CREATE INDEX idx_chat_messages_credit_cost ON chat_messages(session_id, credit_cost) WHERE credit_cost > 0;

-- Add same fields to chat_sessions for cumulative tracking
ALTER TABLE chat_sessions
ADD COLUMN total_actual_cost DECIMAL(10, 6) NOT NULL DEFAULT 0;

COMMENT ON COLUMN chat_sessions.total_actual_cost IS 'Cumulative raw Google API cost in dollars for this session';

ALTER TABLE chat_sessions
ADD COLUMN total_modified_cost DECIMAL(10, 6) NOT NULL DEFAULT 0;

COMMENT ON COLUMN chat_sessions.total_modified_cost IS 'Cumulative cost with markup applied for this session';

ALTER TABLE chat_sessions
ADD COLUMN total_credit_cost INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN chat_sessions.total_credit_cost IS 'Cumulative credits consumed for this session';

ALTER TABLE chat_sessions
ADD COLUMN total_actual_charge DECIMAL(10, 6) NOT NULL DEFAULT 0;

COMMENT ON COLUMN chat_sessions.total_actual_charge IS 'Cumulative dollar amount charged for this session';

-- Backfill total_actual_cost from existing total_credits_used (which was misused to store dollar amounts)
UPDATE chat_sessions
SET total_actual_cost = total_credits_used
WHERE total_credits_used > 0;
