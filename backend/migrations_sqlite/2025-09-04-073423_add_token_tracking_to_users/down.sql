-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.506172
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove token tracking fields from users table
DROP INDEX IF EXISTS idx_users_token_usage_updated_at;

ALTER TABLE users
DROP COLUMN IF EXISTS total_prompt_tokens,
DROP COLUMN IF EXISTS total_completion_tokens,
DROP COLUMN IF EXISTS total_token_cost_cents,
DROP COLUMN IF EXISTS tokens_last_reset_at,
DROP COLUMN IF EXISTS token_usage_updated_at;
