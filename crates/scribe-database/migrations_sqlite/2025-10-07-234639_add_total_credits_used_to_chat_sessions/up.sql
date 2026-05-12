-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.506845
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add total_credits_used column to track cumulative credits with 20% markup
ALTER TABLE chat_sessions
ADD COLUMN total_credits_used INTEGER NOT NULL DEFAULT 0;

-- Add comment explaining the column
-- COMMENT ON COLUMN chat_sessions.total_credits_used IS 'Cumulative credits used for this session (includes 20% markup over API costs)';
