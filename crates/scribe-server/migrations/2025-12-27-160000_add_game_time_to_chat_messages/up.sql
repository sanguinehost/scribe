-- Add game_time to chat_messages
-- This stores the in-game time when the message was sent, for RAG context.
ALTER TABLE chat_messages ADD COLUMN game_time JSONB DEFAULT NULL;
