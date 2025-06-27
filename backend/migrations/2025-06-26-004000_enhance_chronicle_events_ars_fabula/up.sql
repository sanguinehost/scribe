-- Enhance chronicle_events table with Ars Fabula fields
-- Part 1: Add new fields for enhanced narrative event schema

ALTER TABLE chronicle_events
ADD COLUMN IF NOT EXISTS timestamp_iso8601 TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS actors JSONB,
ADD COLUMN IF NOT EXISTS action VARCHAR(100),
ADD COLUMN IF NOT EXISTS context_data JSONB,
ADD COLUMN IF NOT EXISTS causality JSONB,
ADD COLUMN IF NOT EXISTS valence JSONB,
ADD COLUMN IF NOT EXISTS modality VARCHAR(50) DEFAULT 'ACTUAL';

-- Set default timestamp for existing events (use created_at)
UPDATE chronicle_events 
SET timestamp_iso8601 = created_at 
WHERE timestamp_iso8601 IS NULL;

-- Make timestamp_iso8601 NOT NULL after setting defaults
ALTER TABLE chronicle_events 
ALTER COLUMN timestamp_iso8601 SET NOT NULL;

-- Set default modality for existing events
UPDATE chronicle_events 
SET modality = 'ACTUAL' 
WHERE modality IS NULL;

-- Create indexes for improved query performance (without CONCURRENTLY for migration)
CREATE INDEX IF NOT EXISTS idx_chronicle_events_timestamp 
ON chronicle_events (timestamp_iso8601);

CREATE INDEX IF NOT EXISTS idx_chronicle_events_action 
ON chronicle_events (action);

CREATE INDEX IF NOT EXISTS idx_chronicle_events_actors 
ON chronicle_events USING GIN (actors);

CREATE INDEX IF NOT EXISTS idx_chronicle_events_causality 
ON chronicle_events USING GIN (causality);

CREATE INDEX IF NOT EXISTS idx_chronicle_events_modality 
ON chronicle_events (modality);

-- Create a composite index for de-duplication queries
CREATE INDEX IF NOT EXISTS idx_chronicle_events_dedup 
ON chronicle_events (action, chronicle_id, user_id, timestamp_iso8601);