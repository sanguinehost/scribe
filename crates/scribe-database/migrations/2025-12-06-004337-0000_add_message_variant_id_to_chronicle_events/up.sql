ALTER TABLE chronicle_events ADD COLUMN message_variant_id UUID REFERENCES message_variants(id);
