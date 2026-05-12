-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.496064
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Create character_lorebooks table for many-to-many relationship between characters and lorebooks
CREATE TABLE character_lorebooks (
    character_id TEXT NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
    lorebook_id TEXT NOT NULL REFERENCES lorebooks(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Primary key on the combination to ensure uniqueness
    PRIMARY KEY (character_id, lorebook_id)
);

-- Create indexes for efficient lookups
CREATE INDEX idx_character_lorebooks_user_id ON character_lorebooks (user_id);
CREATE INDEX idx_character_lorebooks_character_id ON character_lorebooks (character_id);
CREATE INDEX idx_character_lorebooks_lorebook_id ON character_lorebooks (lorebook_id);

-- SQLite trigger for updating timestamps on character_lorebooks
-- Note: This table uses composite primary key, so we match on both columns
CREATE TRIGGER update_character_lorebooks_timestamp
AFTER UPDATE ON character_lorebooks
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE character_lorebooks
    SET updated_at = CURRENT_TIMESTAMP
    WHERE character_id = NEW.character_id AND lorebook_id = NEW.lorebook_id;
END;
