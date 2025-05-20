-- This file should undo anything in `up.sql`

DROP TRIGGER IF EXISTS set_timestamp_chat_character_overrides ON chat_character_overrides;
DROP TABLE IF EXISTS chat_character_overrides;
