-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.492556
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here
ALTER TABLE chat_sessions ADD COLUMN active_custom_persona_id TEXT REFERENCES user_personas(id) ON DELETE SET NULL;
ALTER TABLE chat_sessions ADD COLUMN active_impersonated_character_id TEXT REFERENCES characters(id) ON DELETE SET NULL;
