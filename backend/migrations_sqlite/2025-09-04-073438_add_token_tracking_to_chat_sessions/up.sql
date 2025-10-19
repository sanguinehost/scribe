-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.506272
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add token tracking fields to chat_sessions table for per-chat usage tracking
ALTER TABLE chat_sessions
ADD COLUMN total_prompt_tokens INTEGER NOT NULL DEFAULT 0,
ADD COLUMN total_completion_tokens INTEGER NOT NULL DEFAULT 0,
ADD COLUMN estimated_cost_cents INTEGER NOT NULL DEFAULT 0,
ADD COLUMN tokens_counted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Add index for efficient chat token queries
CREATE INDEX idx_chat_sessions_tokens_counted_at ON chat_sessions (tokens_counted_at);
