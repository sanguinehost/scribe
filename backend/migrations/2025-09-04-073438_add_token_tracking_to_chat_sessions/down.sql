-- Remove token tracking fields from chat_sessions table
DROP INDEX IF EXISTS idx_chat_sessions_tokens_counted_at;

ALTER TABLE chat_sessions
DROP COLUMN IF EXISTS total_prompt_tokens,
DROP COLUMN IF EXISTS total_completion_tokens,
DROP COLUMN IF EXISTS estimated_cost_cents,
DROP COLUMN IF EXISTS tokens_counted_at;