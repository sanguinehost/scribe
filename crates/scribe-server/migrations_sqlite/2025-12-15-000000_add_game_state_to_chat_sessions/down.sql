-- Rollback game_state and game_master_mode_enabled columns

-- Drop index first
DROP INDEX IF EXISTS idx_chat_sessions_game_master_mode;

-- SQLite doesn't support DROP COLUMN directly
-- Need to recreate the table without these columns
-- For now, this is a no-op as SQLite 3.35+ supports ALTER TABLE DROP COLUMN
-- Note: This migration may not be reversible on older SQLite versions
