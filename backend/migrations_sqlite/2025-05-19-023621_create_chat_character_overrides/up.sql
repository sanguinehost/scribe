-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:00:19.545243
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here

CREATE TABLE IF NOT EXISTS chat_character_overrides (
    id TEXT PRIMARY KEY ,
    chat_session_id TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    original_character_id TEXT NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
    field_name TEXT NOT NULL,
    overridden_value BLOB NOT NULL,
    overridden_value_nonce BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_chat_character_override UNIQUE (chat_session_id, original_character_id, field_name)
);

-- Create a trigger to automatically update updated_at
-- Attempt to drop trigger first to make it idempotent, then create.
DROP TRIGGER IF EXISTS set_timestamp_chat_character_overrides ON chat_character_overrides;
CREATE TRIGGER set_timestamp_chat_character_overrides
BEFORE UPDATE ON chat_character_overrides
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();
