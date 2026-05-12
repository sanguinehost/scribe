-- Rollback: Remove token tracking columns from message_variants table
ALTER TABLE message_variants DROP COLUMN model_name;
ALTER TABLE message_variants DROP COLUMN completion_tokens;
ALTER TABLE message_variants DROP COLUMN prompt_tokens;
