-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:00:19.549859
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Create table for tracking character lorebook overrides at the chat level
CREATE TABLE chat_character_lorebook_overrides (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_session_id TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    lorebook_id TEXT NOT NULL REFERENCES lorebooks(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('disable', 'enable')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Ensure only one override per chat-lorebook combination
    UNIQUE(chat_session_id, lorebook_id)
);

-- Create indexes for performance
CREATE INDEX idx_chat_character_lorebook_overrides_chat_session_id
    ON chat_character_lorebook_overrides(chat_session_id);
CREATE INDEX idx_chat_character_lorebook_overrides_lorebook_id
    ON chat_character_lorebook_overrides(lorebook_id);
CREATE INDEX idx_chat_character_lorebook_overrides_user_id
    ON chat_character_lorebook_overrides(user_id);

-- Create updated_at trigger
DROP TRIGGER IF EXISTS set_timestamp_chat_character_lorebook_overrides ON chat_character_lorebook_overrides;
CREATE TRIGGER set_timestamp_chat_character_lorebook_overrides
    BEFORE UPDATE ON chat_character_lorebook_overrides
    FOR EACH ROW
    EXECUTE FUNCTION trigger_set_timestamp();
