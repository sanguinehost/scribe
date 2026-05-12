-- This file should undo anything in `up.sql`

-- Drop the trigger first
DROP TRIGGER IF EXISTS template_preferences_updated_at_trigger ON template_preferences;

-- Drop the function
DROP FUNCTION IF EXISTS update_template_preferences_updated_at();

-- Drop indexes
DROP INDEX IF EXISTS idx_template_preferences_character_id;
DROP INDEX IF EXISTS idx_template_preferences_user_id;

-- Drop the table
DROP TABLE IF EXISTS template_preferences;
