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

-- Add a trigger to automatically update the updated_at column
-- CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NO... -- Removed: SQLite does not support PL/pgSQL


-- SQLite trigger for updating timestamps on character_lorebooks
CREATE TRIGGER IF NOT EXISTS update_character_lorebooks_timestamp
AFTER UPDATE ON character_lorebooks
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE character_lorebooks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
