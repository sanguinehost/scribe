-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.501560
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add binary data field to character_assets table for storing image data directly
ALTER TABLE character_assets ADD COLUMN data BLOB;
ALTER TABLE character_assets ALTER COLUMN uri DROP NOT NULL;

-- Add content_type field to properly identify the image format
ALTER TABLE character_assets ADD COLUMN content_type TEXT;

-- Update existing records to set appropriate defaults
UPDATE character_assets SET content_type = 'image/png' WHERE asset_type = 'avatar' AND content_type IS NULL;

-- Create a general assets table for user and persona avatars
CREATE TABLE user_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    persona_id TEXT REFERENCES user_personas(id) ON DELETE CASCADE, -- NULL for user avatars, populated for persona avatars
    asset_type TEXT NOT NULL, -- 'avatar', etc.
    uri TEXT, -- Optional: for URL/path reference
    name TEXT NOT NULL,
    ext TEXT NOT NULL,
    data BLOB, -- Binary image data
    content_type TEXT, -- 'image/png', 'image/jpeg', etc.
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Ensure user can't have multiple avatars (but can have multiple persona avatars)
    CONSTRAINT unique_user_avatar UNIQUE (user_id, asset_type) DEFERRABLE INITIALLY DEFERRED,
    -- Ensure persona can't have multiple avatars
    CONSTRAINT unique_persona_avatar UNIQUE (persona_id, asset_type) DEFERRABLE INITIALLY DEFERRED,
    -- Check constraint: either user avatar (persona_id is NULL) or persona avatar (persona_id is NOT NULL)
    CONSTRAINT check_user_or_persona CHECK (
        (persona_id IS NULL AND asset_type = 'avatar') OR
        (persona_id IS NOT NULL AND asset_type = 'avatar')
    )
);

-- Add triggers for updated_at

-- SQLite trigger for updating timestamps on user_assets
CREATE TRIGGER IF NOT EXISTS update_user_assets_timestamp
AFTER UPDATE ON user_assets
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE user_assets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Add indexes for performance
CREATE INDEX idx_user_assets_user_id ON user_assets (user_id);
CREATE INDEX idx_user_assets_persona_id ON user_assets (persona_id);
CREATE INDEX idx_user_assets_type ON user_assets (asset_type);
