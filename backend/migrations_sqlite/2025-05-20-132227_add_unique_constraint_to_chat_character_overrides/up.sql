-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.500520
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

ALTER TABLE chat_character_overrides
ADD CONSTRAINT chat_character_overrides_session_id_field_name_key UNIQUE (chat_session_id, field_name);
