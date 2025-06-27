-- Revert Ars Fabula enhancements to chronicle_events table

-- Drop indexes
DROP INDEX IF EXISTS idx_chronicle_events_dedup;
DROP INDEX IF EXISTS idx_chronicle_events_modality;
DROP INDEX IF EXISTS idx_chronicle_events_causality;
DROP INDEX IF EXISTS idx_chronicle_events_actors;
DROP INDEX IF EXISTS idx_chronicle_events_action;
DROP INDEX IF EXISTS idx_chronicle_events_timestamp;

-- Remove new columns
ALTER TABLE chronicle_events
DROP COLUMN IF EXISTS timestamp_iso8601,
DROP COLUMN IF EXISTS actors,
DROP COLUMN IF EXISTS action,
DROP COLUMN IF EXISTS context_data,
DROP COLUMN IF EXISTS causality,
DROP COLUMN IF EXISTS valence,
DROP COLUMN IF EXISTS modality;