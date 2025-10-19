-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:00:19.545467
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- This file should undo anything in `up.sql`

DROP TRIGGER IF EXISTS set_timestamp_chat_character_overrides ON chat_character_overrides;
DROP TABLE IF EXISTS chat_character_overrides;
