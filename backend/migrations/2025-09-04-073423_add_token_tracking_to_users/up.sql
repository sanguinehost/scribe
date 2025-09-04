-- Add token tracking fields to users table for billing and usage analytics
ALTER TABLE users
ADD COLUMN total_prompt_tokens BIGINT NOT NULL DEFAULT 0,
ADD COLUMN total_completion_tokens BIGINT NOT NULL DEFAULT 0,
ADD COLUMN total_token_cost_cents BIGINT NOT NULL DEFAULT 0,
ADD COLUMN tokens_last_reset_at TIMESTAMPTZ DEFAULT NULL,
ADD COLUMN token_usage_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Add index for efficient user token queries
CREATE INDEX idx_users_token_usage_updated_at ON users (token_usage_updated_at);