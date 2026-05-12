-- Add token tracking columns to message_variants table
ALTER TABLE message_variants ADD COLUMN prompt_tokens INTEGER;
ALTER TABLE message_variants ADD COLUMN completion_tokens INTEGER;
ALTER TABLE message_variants ADD COLUMN model_name TEXT;
