-- up.sql
ALTER TABLE cognitive_facts ADD COLUMN message_variant_id BLOB REFERENCES message_variants(id) ON DELETE CASCADE;
ALTER TABLE character_opinions ADD COLUMN message_variant_id BLOB REFERENCES message_variants(id) ON DELETE CASCADE;
ALTER TABLE entity_observations ADD COLUMN message_variant_id BLOB REFERENCES message_variants(id) ON DELETE CASCADE;

CREATE INDEX idx_cognitive_facts_message_variant_id ON cognitive_facts(message_variant_id);
CREATE INDEX idx_character_opinions_message_variant_id ON character_opinions(message_variant_id);
CREATE INDEX idx_entity_observations_message_variant_id ON entity_observations(message_variant_id);
