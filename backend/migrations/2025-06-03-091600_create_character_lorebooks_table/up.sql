-- Create character_lorebooks table for many-to-many relationship between characters and lorebooks
CREATE TABLE character_lorebooks (
    character_id UUID NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
    lorebook_id UUID NOT NULL REFERENCES lorebooks(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Primary key on the combination to ensure uniqueness
    PRIMARY KEY (character_id, lorebook_id)
);

-- Create indexes for efficient lookups
CREATE INDEX idx_character_lorebooks_user_id ON character_lorebooks (user_id);
CREATE INDEX idx_character_lorebooks_character_id ON character_lorebooks (character_id);
CREATE INDEX idx_character_lorebooks_lorebook_id ON character_lorebooks (lorebook_id);

-- Add a trigger to automatically update the updated_at column
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_timestamp
    BEFORE UPDATE ON character_lorebooks
    FOR EACH ROW
    EXECUTE FUNCTION trigger_set_timestamp();