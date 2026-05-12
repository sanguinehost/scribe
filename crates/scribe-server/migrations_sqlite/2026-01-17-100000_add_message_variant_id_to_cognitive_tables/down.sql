-- down.sql
DROP INDEX IF EXISTS idx_entity_observations_message_variant_id;
DROP INDEX IF EXISTS idx_character_opinions_message_variant_id;
DROP INDEX IF EXISTS idx_cognitive_facts_message_variant_id;

-- SQLite doesn't support DROP COLUMN in older versions, but we'll try it anyway
-- If it fails, we might need to recreate the table, but for a dev migration this is usually fine
ALTER TABLE entity_observations DROP COLUMN message_variant_id;
ALTER TABLE character_opinions DROP COLUMN message_variant_id;
ALTER TABLE cognitive_facts DROP COLUMN message_variant_id;
