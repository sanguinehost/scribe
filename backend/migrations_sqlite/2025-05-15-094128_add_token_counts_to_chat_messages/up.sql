-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.500410
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

ALTER TABLE chat_messages
ADD COLUMN prompt_tokens INTEGER,
ADD COLUMN completion_tokens INTEGER;
