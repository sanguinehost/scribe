-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.496332
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop the character_lorebooks table and related triggers/indexes
DROP TRIGGER IF EXISTS set_timestamp ON character_lorebooks;
DROP INDEX IF EXISTS idx_character_lorebooks_user_id;
DROP INDEX IF EXISTS idx_character_lorebooks_character_id;
DROP INDEX IF EXISTS idx_character_lorebooks_lorebook_id;
DROP TABLE IF EXISTS character_lorebooks;
