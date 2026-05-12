-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.489609
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add columns for chat generation settings to the chat_sessions table

ALTER TABLE chat_sessions ADD COLUMN frequency_penalty NUMERIC NULL;
ALTER TABLE chat_sessions ADD COLUMN presence_penalty NUMERIC NULL;
ALTER TABLE chat_sessions ADD COLUMN top_k INTEGER NULL;
ALTER TABLE chat_sessions ADD COLUMN top_p NUMERIC NULL;
ALTER TABLE chat_sessions ADD COLUMN repetition_penalty NUMERIC NULL;
ALTER TABLE chat_sessions ADD COLUMN min_p NUMERIC NULL;
ALTER TABLE chat_sessions ADD COLUMN top_a NUMERIC NULL;
ALTER TABLE chat_sessions ADD COLUMN seed INTEGER NULL;
ALTER TABLE chat_sessions ADD COLUMN logit_bias TEXT NULL;
