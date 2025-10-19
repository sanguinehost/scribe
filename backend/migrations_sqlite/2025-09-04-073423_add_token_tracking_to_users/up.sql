-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.506030
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add token tracking fields to users table for billing and usage analytics
ALTER TABLE users
ADD COLUMN total_prompt_tokens INTEGER NOT NULL DEFAULT 0,
ADD COLUMN total_completion_tokens INTEGER NOT NULL DEFAULT 0,
ADD COLUMN total_token_cost_cents INTEGER NOT NULL DEFAULT 0,
ADD COLUMN tokens_last_reset_at DATETIME DEFAULT NULL,
ADD COLUMN token_usage_updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Add index for efficient user token queries
CREATE INDEX idx_users_token_usage_updated_at ON users (token_usage_updated_at);
