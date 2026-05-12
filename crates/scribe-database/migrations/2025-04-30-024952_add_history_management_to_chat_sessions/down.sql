-- This file should undo anything in `up.sql`
ALTER TABLE chat_sessions
DROP COLUMN history_management_strategy,
DROP COLUMN history_management_limit;
