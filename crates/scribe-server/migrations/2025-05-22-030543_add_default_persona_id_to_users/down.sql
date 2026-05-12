ALTER TABLE users
DROP CONSTRAINT IF EXISTS fk_default_user_persona,
DROP COLUMN IF EXISTS default_persona_id;
