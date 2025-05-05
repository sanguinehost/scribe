-- This file should undo anything in `up.sql`

-- Remove model_name column from chat_sessions table
ALTER TABLE chat_sessions
DROP COLUMN model_name;
