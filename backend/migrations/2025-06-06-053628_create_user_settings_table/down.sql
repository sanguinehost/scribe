-- Drop user_settings table and related objects

-- Drop trigger first
DROP TRIGGER IF EXISTS trigger_update_user_settings_updated_at ON user_settings;

-- Drop function
DROP FUNCTION IF EXISTS update_user_settings_updated_at();

-- Drop index
DROP INDEX IF EXISTS idx_user_settings_user_id;

-- Drop table
DROP TABLE IF EXISTS user_settings;