-- Remove token count and model name columns from message_variants
ALTER TABLE message_variants DROP COLUMN IF EXISTS prompt_tokens;
ALTER TABLE message_variants DROP COLUMN IF EXISTS completion_tokens;
ALTER TABLE message_variants DROP COLUMN IF EXISTS model_name;
