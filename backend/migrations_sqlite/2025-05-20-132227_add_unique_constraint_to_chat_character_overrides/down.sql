-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.500585
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

ALTER TABLE chat_character_overrides
DROP CONSTRAINT IF EXISTS chat_character_overrides_session_id_field_name_key;
