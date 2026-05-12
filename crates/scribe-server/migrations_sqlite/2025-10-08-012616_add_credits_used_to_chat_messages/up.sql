-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.506999
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add credits_charged column to track actual credits deducted from user balance
ALTER TABLE chat_messages
ADD COLUMN credits_charged INTEGER NOT NULL DEFAULT 0;

-- Add credits_cost column to track theoretical cost regardless of tier/limits
ALTER TABLE chat_messages
ADD COLUMN credits_cost INTEGER NOT NULL DEFAULT 0;

-- Add comments explaining the columns
-- COMMENT ON COLUMN chat_messages.credits_charged IS 'Actual credits deducted from user balance (0 for free tier Flash within limits, >0 only when charged)';
-- COMMENT ON COLUMN chat_messages.credits_cost IS 'Theoretical cost based on tokens and model pricing (always calculated, used for metrics and cost analysis)';

-- Add indexes for efficient queries
CREATE INDEX idx_chat_messages_session_charged ON chat_messages(session_id, credits_charged) WHERE credits_charged > 0;
CREATE INDEX idx_chat_messages_session_cost ON chat_messages(session_id, credits_cost) WHERE credits_cost > 0;
