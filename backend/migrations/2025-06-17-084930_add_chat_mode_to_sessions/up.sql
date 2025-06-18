-- Add chat_mode column to chat_sessions table
-- Default to 'Character' to maintain compatibility with existing sessions
ALTER TABLE chat_sessions 
ADD COLUMN chat_mode VARCHAR NOT NULL DEFAULT 'Character';

-- Make character_id nullable to support non-character modes
ALTER TABLE chat_sessions 
ALTER COLUMN character_id DROP NOT NULL;
