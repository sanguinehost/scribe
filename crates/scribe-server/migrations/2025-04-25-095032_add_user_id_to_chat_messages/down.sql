-- This file should undo anything in `up.sql`

ALTER TABLE chat_messages
DROP CONSTRAINT IF EXISTS fk_chat_messages_user;

DROP INDEX IF EXISTS idx_chat_messages_user_id;

ALTER TABLE chat_messages
DROP COLUMN IF EXISTS user_id;
