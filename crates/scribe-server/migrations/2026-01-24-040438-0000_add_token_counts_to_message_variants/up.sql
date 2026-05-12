-- Add token count and model name columns to message_variants
ALTER TABLE message_variants ADD COLUMN prompt_tokens BIGINT;
ALTER TABLE message_variants ADD COLUMN completion_tokens BIGINT;
ALTER TABLE message_variants ADD COLUMN model_name TEXT;
