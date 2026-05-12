-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.490093
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- This file should undo anything in `up.sql`

ALTER TABLE chat_messages
DROP CONSTRAINT IF EXISTS fk_chat_messages_user;

DROP INDEX IF EXISTS idx_chat_messages_user_id;

ALTER TABLE chat_messages
DROP COLUMN IF EXISTS user_id;
