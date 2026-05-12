-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.507212
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove both credits columns and indexes
DROP INDEX IF EXISTS idx_chat_messages_session_charged;
DROP INDEX IF EXISTS idx_chat_messages_session_cost;

ALTER TABLE chat_messages
DROP COLUMN credits_charged,
DROP COLUMN credits_cost;
