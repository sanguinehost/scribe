ALTER TABLE chronicle_events ADD COLUMN message_variant_id TEXT REFERENCES message_variants(id);
