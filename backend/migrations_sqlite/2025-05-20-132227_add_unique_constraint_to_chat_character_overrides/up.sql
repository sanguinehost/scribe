-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.500520
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- SQLite doesn't support ALTER TABLE ADD CONSTRAINT for UNIQUE constraints
-- Use CREATE UNIQUE INDEX instead
CREATE UNIQUE INDEX idx_chat_character_overrides_session_field
ON chat_character_overrides(chat_session_id, field_name);
