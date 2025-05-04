-- Add columns to chat_sessions if they don't exist
ALTER TABLE IF EXISTS chat_sessions ADD COLUMN IF NOT EXISTS visibility VARCHAR(50) DEFAULT 'private';

-- Add columns to chat_messages if they don't exist
ALTER TABLE IF EXISTS chat_messages ADD COLUMN IF NOT EXISTS role VARCHAR(50);
ALTER TABLE IF EXISTS chat_messages ADD COLUMN IF NOT EXISTS parts JSONB;
ALTER TABLE IF EXISTS chat_messages ADD COLUMN IF NOT EXISTS attachments JSONB; 