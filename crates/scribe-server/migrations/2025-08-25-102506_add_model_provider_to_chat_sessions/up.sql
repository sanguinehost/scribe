-- Add model_provider column to chat_sessions table (nullable initially)
ALTER TABLE chat_sessions ADD COLUMN model_provider VARCHAR(50);

-- Set default provider to 'gemini' for all existing records
-- Users can re-select local models if needed
UPDATE chat_sessions SET model_provider = 'gemini' WHERE model_provider IS NULL;
