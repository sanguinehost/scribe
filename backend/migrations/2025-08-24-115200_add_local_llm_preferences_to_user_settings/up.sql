-- Add local LLM preferences to user_settings table
-- These fields store user's local model preferences and settings

-- Preferred local model name (filename without extension)
ALTER TABLE user_settings 
ADD COLUMN preferred_local_model VARCHAR(255) DEFAULT NULL;

-- Whether user has local LLM enabled/preferred
ALTER TABLE user_settings 
ADD COLUMN local_llm_enabled BOOLEAN DEFAULT FALSE;

-- JSON field for future local model preferences/settings
-- This allows extensibility without schema changes
ALTER TABLE user_settings 
ADD COLUMN local_model_preferences JSONB DEFAULT NULL;

-- Add index on preferred_local_model for faster lookups
CREATE INDEX idx_user_settings_preferred_local_model ON user_settings(preferred_local_model);
