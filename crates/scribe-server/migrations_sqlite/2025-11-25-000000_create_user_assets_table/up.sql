-- Create user_assets table for SQLite
-- Matches PostgreSQL migration 2025-06-06-142918_add_avatar_data_to_character_assets

CREATE TABLE user_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    persona_id TEXT REFERENCES user_personas(id) ON DELETE CASCADE, -- NULL for user avatars
    asset_type TEXT NOT NULL, -- 'avatar', etc.
    uri TEXT, -- Optional: for URL/path reference
    name TEXT NOT NULL,
    ext TEXT NOT NULL,
    data BLOB, -- Binary image data
    content_type TEXT, -- 'image/png', etc.
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Ensure user can't have multiple avatars (but can have multiple persona avatars)
    CONSTRAINT unique_user_avatar UNIQUE (user_id, asset_type),
    -- Ensure persona can't have multiple avatars
    CONSTRAINT unique_persona_avatar UNIQUE (persona_id, asset_type),
    -- Check constraint: either user avatar (persona_id is NULL) or persona avatar (persona_id is NOT NULL)
    CONSTRAINT check_user_or_persona CHECK (
        (persona_id IS NULL AND asset_type = 'avatar') OR
        (persona_id IS NOT NULL AND asset_type = 'avatar')
    )
);

-- Indexes
CREATE INDEX idx_user_assets_user_id ON user_assets (user_id);
CREATE INDEX idx_user_assets_persona_id ON user_assets (persona_id);
CREATE INDEX idx_user_assets_type ON user_assets (asset_type);

-- Trigger for updated_at
CREATE TRIGGER IF NOT EXISTS update_user_assets_timestamp
AFTER UPDATE ON user_assets
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE user_assets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
