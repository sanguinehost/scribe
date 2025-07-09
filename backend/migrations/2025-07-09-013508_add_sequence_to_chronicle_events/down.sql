-- Remove sequence number field and index
DROP INDEX IF EXISTS idx_chronicle_events_sequence;
ALTER TABLE chronicle_events DROP COLUMN IF EXISTS sequence_number;
