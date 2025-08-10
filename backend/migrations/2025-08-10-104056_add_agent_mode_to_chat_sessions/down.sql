-- Drop the index
DROP INDEX IF EXISTS idx_chat_sessions_agent_mode;

-- Remove the agent_mode column
ALTER TABLE chat_sessions DROP COLUMN agent_mode;