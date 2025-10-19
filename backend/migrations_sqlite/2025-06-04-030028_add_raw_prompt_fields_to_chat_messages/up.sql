-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.500860
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add encrypted fields to store raw prompt debugging information
-- These fields will contain the complete prompt sent to the AI, including:
-- - System prompt
-- - RAG context from lorebooks
-- - Conversation history
-- - User's message
-- Only the message author can decrypt this information

ALTER TABLE chat_messages
ADD COLUMN raw_prompt_ciphertext BLOB,
ADD COLUMN raw_prompt_nonce BLOB;

-- Add indexes for better query performance when filtering by these fields
CREATE INDEX idx_chat_messages_raw_prompt_exists
ON chat_messages (user_id, session_id)
WHERE raw_prompt_ciphertext IS NOT NULL;
