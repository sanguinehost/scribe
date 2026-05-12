-- This file should undo anything in `up.sql`
ALTER TABLE chat_session_lorebooks
DROP COLUMN created_at,
DROP COLUMN updated_at;
