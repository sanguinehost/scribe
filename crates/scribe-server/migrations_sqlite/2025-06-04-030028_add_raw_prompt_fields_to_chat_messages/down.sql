-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.501017
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove raw prompt debugging fields

DROP INDEX IF EXISTS idx_chat_messages_raw_prompt_exists;

ALTER TABLE chat_messages
DROP COLUMN IF EXISTS raw_prompt_ciphertext,
DROP COLUMN IF EXISTS raw_prompt_nonce;
