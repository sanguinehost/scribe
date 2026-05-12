-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.501458
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop user_settings table and related objects

-- Drop trigger first
DROP TRIGGER IF EXISTS trigger_update_user_settings_updated_at ON user_settings;

-- Drop function
DROP FUNCTION IF EXISTS update_user_settings_updated_at();

-- Drop index
DROP INDEX IF EXISTS idx_user_settings_user_id;

-- Drop table
DROP TABLE IF EXISTS user_settings;
