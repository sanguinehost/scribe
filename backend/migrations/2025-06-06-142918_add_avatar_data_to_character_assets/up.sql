-- Add binary data field to character_assets table for storing image data directly
ALTER TABLE character_assets ADD COLUMN data BYTEA;
ALTER TABLE character_assets ALTER COLUMN uri DROP NOT NULL;

-- Add content_type field to properly identify the image format
ALTER TABLE character_assets ADD COLUMN content_type VARCHAR(100);

-- Update existing records to set appropriate defaults
UPDATE character_assets SET content_type = 'image/png' WHERE asset_type = 'avatar' AND content_type IS NULL;

-- Create a general assets table for user and persona avatars
CREATE TABLE user_assets (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    persona_id UUID REFERENCES user_personas(id) ON DELETE CASCADE, -- NULL for user avatars, populated for persona avatars
    asset_type VARCHAR(50) NOT NULL, -- 'avatar', etc.
    uri TEXT, -- Optional: for URL/path reference
    name VARCHAR(255) NOT NULL,
    ext VARCHAR(50) NOT NULL,
    data BYTEA, -- Binary image data
    content_type VARCHAR(100), -- 'image/png', 'image/jpeg', etc.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
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
SELECT diesel_manage_updated_at('user_assets');

-- Add indexes for performance
CREATE INDEX idx_user_assets_user_id ON user_assets (user_id);
CREATE INDEX idx_user_assets_persona_id ON user_assets (persona_id);
CREATE INDEX idx_user_assets_type ON user_assets (asset_type);
