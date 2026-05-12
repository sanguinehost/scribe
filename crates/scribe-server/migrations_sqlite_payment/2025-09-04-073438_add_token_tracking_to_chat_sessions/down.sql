-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.506401
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove token tracking fields from chat_sessions table
DROP INDEX IF EXISTS idx_chat_sessions_tokens_counted_at;

ALTER TABLE chat_sessions
DROP COLUMN IF EXISTS total_prompt_tokens,
DROP COLUMN IF EXISTS total_completion_tokens,
DROP COLUMN IF EXISTS estimated_cost_cents,
DROP COLUMN IF EXISTS tokens_counted_at;
