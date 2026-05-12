-- Your SQL goes here
ALTER TABLE chat_sessions
ADD COLUMN history_management_strategy TEXT NOT NULL DEFAULT 'none',
ADD COLUMN history_management_limit INTEGER NOT NULL DEFAULT 4096;

-- Add constraints if necessary, e.g., CHECK constraint for strategy values
-- ALTER TABLE chat_sessions
-- ADD CONSTRAINT check_history_strategy CHECK (history_management_strategy IN ('sliding_window_tokens', 'sliding_window_messages', 'truncate_tokens', 'none'));
-- Note: Using a CHECK constraint might be better, but TEXT is simpler for now.
