-- This file should undo anything in `up.sql`

ALTER TABLE chat_sessions
DROP CONSTRAINT IF EXISTS only_one_active_persona,
DROP COLUMN IF EXISTS active_impersonated_character_id,
DROP COLUMN IF EXISTS active_custom_persona_id;
