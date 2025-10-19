-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:00:19.550168
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop the chat character lorebook overrides table
DROP TRIGGER IF EXISTS set_timestamp_chat_character_lorebook_overrides ON chat_character_lorebook_overrides;
DROP TABLE IF EXISTS chat_character_lorebook_overrides;
