-- Fix NULL values in characters table (array columns)
UPDATE characters SET tags = '[]' WHERE tags IS NULL;
UPDATE characters SET alternate_greetings = '[]' WHERE alternate_greetings IS NULL;
UPDATE characters SET system_tags = '[]' WHERE system_tags IS NULL;
UPDATE characters SET source = '[]' WHERE source IS NULL;
UPDATE characters SET group_only_greetings = '[]' WHERE group_only_greetings IS NULL;

-- Fix NULL values in characters table (JSON columns)
UPDATE characters SET extensions = '{}' WHERE extensions IS NULL;
UPDATE characters SET usage_hints = '{}' WHERE usage_hints IS NULL;
UPDATE characters SET creator_notes_multilingual = '{}' WHERE creator_notes_multilingual IS NULL;

-- Fix NULL values in user_settings table (JSON columns)
UPDATE user_settings SET local_model_preferences = '{}' WHERE local_model_preferences IS NULL;
