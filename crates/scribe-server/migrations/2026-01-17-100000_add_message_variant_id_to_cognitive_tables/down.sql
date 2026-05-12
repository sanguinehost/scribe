-- down.sql
DROP INDEX IF EXISTS idx_entity_observations_message_variant_id;
DROP INDEX IF EXISTS idx_character_opinions_message_variant_id;
DROP INDEX IF EXISTS idx_cognitive_facts_message_variant_id;

ALTER TABLE entity_observations DROP COLUMN IF EXISTS message_variant_id;
ALTER TABLE character_opinions DROP COLUMN IF EXISTS message_variant_id;
ALTER TABLE cognitive_facts DROP COLUMN IF EXISTS message_variant_id;
