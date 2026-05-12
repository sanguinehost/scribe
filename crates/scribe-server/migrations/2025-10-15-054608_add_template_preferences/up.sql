-- Create template_preferences table to store user's narrative style preferences
-- These are UI/UX preferences (similar to user_settings), not user-generated content,
-- so they don't require encryption
CREATE TABLE template_preferences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    character_id UUID REFERENCES characters(id) ON DELETE CASCADE,
    template_id VARCHAR(255),  -- null = use system default template

    -- Narrative style variables (enum values, not sensitive content)
    tense VARCHAR(20) NOT NULL DEFAULT 'past-tense',
    narration VARCHAR(20) NOT NULL DEFAULT 'third-person',
    perspective VARCHAR(50) NOT NULL DEFAULT 'omniscient',
    length VARCHAR(50) NOT NULL DEFAULT 'flexible',

    -- Optional enhancements for future use
    enable_info_box BOOLEAN NOT NULL DEFAULT false,
    enable_stats_tracker BOOLEAN NOT NULL DEFAULT false,
    enable_thinking BOOLEAN NOT NULL DEFAULT false,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Ensure one preference per user-character combination
    -- null character_id represents user's default preferences
    UNIQUE(user_id, character_id)
);

-- Create indexes for faster lookups
CREATE INDEX idx_template_preferences_user_id ON template_preferences(user_id);
CREATE INDEX idx_template_preferences_character_id ON template_preferences(character_id) WHERE character_id IS NOT NULL;

-- Add trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_template_preferences_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER template_preferences_updated_at_trigger
BEFORE UPDATE ON template_preferences
FOR EACH ROW
EXECUTE FUNCTION update_template_preferences_updated_at();
