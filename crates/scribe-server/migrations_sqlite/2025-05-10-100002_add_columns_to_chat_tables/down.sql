-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.500312
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop added columns from chat_messages
ALTER TABLE IF EXISTS chat_messages DROP COLUMN IF EXISTS attachments;
ALTER TABLE IF EXISTS chat_messages DROP COLUMN IF EXISTS parts;
ALTER TABLE IF EXISTS chat_messages DROP COLUMN IF EXISTS role;

-- Drop added columns from chat_sessions
ALTER TABLE IF EXISTS chat_sessions DROP COLUMN IF EXISTS visibility;
