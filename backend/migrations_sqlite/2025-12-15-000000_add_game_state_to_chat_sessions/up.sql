-- Add game_state and game_master_mode_enabled to chat_sessions
-- This supports the Game Master Agent feature

-- Add game_state column (TEXT for SQLite, stores JSON)
ALTER TABLE chat_sessions ADD COLUMN game_state TEXT DEFAULT NULL;

-- Add game_master_mode_enabled flag
ALTER TABLE chat_sessions ADD COLUMN game_master_mode_enabled INTEGER NOT NULL DEFAULT 0;

-- Create index for sessions with game master mode enabled
CREATE INDEX idx_chat_sessions_game_master_mode ON chat_sessions(game_master_mode_enabled);
