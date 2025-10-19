-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.508208
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Create template_preferences table to store user's narrative style preferences
-- These are UI/UX preferences (similar to user_settings), not user-generated content,
-- so they don't require encryption
CREATE TABLE template_preferences (
    id TEXT PRIMARY KEY ,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    character_id TEXT REFERENCES characters(id) ON DELETE CASCADE,
    template_id TEXT,  -- null = use system default template

    -- Narrative style variables (enum values, not sensitive content)
    tense TEXT NOT NULL DEFAULT 'past-tense',
    narration TEXT NOT NULL DEFAULT 'third-person',
    perspective TEXT NOT NULL DEFAULT 'omniscient',
    length TEXT NOT NULL DEFAULT 'flexible',

    -- Optional enhancements for future use
    enable_info_box BOOLEAN NOT NULL DEFAULT false,
    enable_stats_tracker BOOLEAN NOT NULL DEFAULT false,
    enable_thinking BOOLEAN NOT NULL DEFAULT false,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Ensure one preference per user-character combination
    -- null character_id represents user's default preferences
    UNIQUE(user_id, character_id)
);

-- Create indexes for faster lookups
CREATE INDEX idx_template_preferences_user_id ON template_preferences(user_id);
CREATE INDEX idx_template_preferences_character_id ON template_preferences(character_id) WHERE character_id IS NOT NULL;

-- Add trigger to update updated_at DATETIME
-- CREATE OR REPLACE FUNCTION update_template_preferences_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    ... -- Removed: SQLite does not support PL/pgSQL


-- SQLite trigger for updating timestamps on template_preferences
CREATE TRIGGER IF NOT EXISTS update_template_preferences_timestamp
AFTER UPDATE ON template_preferences
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE template_preferences SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
