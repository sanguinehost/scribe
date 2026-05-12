-- Remove token tracking fields from users table
DROP INDEX IF EXISTS idx_users_token_usage_updated_at;

ALTER TABLE users
DROP COLUMN IF EXISTS total_prompt_tokens,
DROP COLUMN IF EXISTS total_completion_tokens,
DROP COLUMN IF EXISTS total_token_cost_cents,
DROP COLUMN IF EXISTS tokens_last_reset_at,
DROP COLUMN IF EXISTS token_usage_updated_at;
