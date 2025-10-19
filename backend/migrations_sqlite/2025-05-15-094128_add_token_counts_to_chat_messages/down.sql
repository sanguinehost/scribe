-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.500466
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

ALTER TABLE chat_messages
DROP COLUMN prompt_tokens,
DROP COLUMN completion_tokens;
