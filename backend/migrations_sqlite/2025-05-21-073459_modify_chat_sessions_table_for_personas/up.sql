-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:00:19.545856
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here
ALTER TABLE chat_sessions
ADD COLUMN active_custom_persona_id TEXT REFERENCES user_personas(id) ON DELETE SET NULL,
ADD COLUMN active_impersonated_character_id TEXT REFERENCES characters(id) ON DELETE SET NULL,
ADD CONSTRAINT only_one_active_persona CHECK (active_custom_persona_id IS NULL OR active_impersonated_character_id IS NULL);
