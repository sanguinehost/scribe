-- Rollback game_state and game_master_mode_enabled columns

-- Drop index first
DROP INDEX IF EXISTS idx_chat_sessions_game_master_mode;

-- Remove columns
-- Note: SQLite doesn't support DROP COLUMN in older versions, but Diesel handles this
ALTER TABLE chat_sessions DROP COLUMN game_master_mode_enabled;
ALTER TABLE chat_sessions DROP COLUMN game_state;
