-- Add game_state and game_master_mode_enabled to chat_sessions
-- This supports the Game Master Agent feature

-- Add game_state column (TEXT for SQLite compatibility, JSONB-like usage in Postgres)
ALTER TABLE chat_sessions ADD COLUMN game_state TEXT DEFAULT NULL;

-- Add game_master_mode_enabled flag
ALTER TABLE chat_sessions ADD COLUMN game_master_mode_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Create index for sessions with game master mode enabled
-- Note: Using simple index instead of partial index for SQLite compatibility
CREATE INDEX idx_chat_sessions_game_master_mode ON chat_sessions(game_master_mode_enabled);
