-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.498555
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Enhance chronicle_events table with Ars Fabula fields
-- Part 1: Add new fields for enhanced narrative event schema

-- Note: SQLite doesn't support IF NOT EXISTS in ALTER TABLE ADD COLUMN (before 3.35.0)
-- Since migrations run in sequence, columns shouldn't exist yet, so this is safe


ALTER TABLE chronicle_events ADD COLUMN timestamp_iso8601 DATETIME;
ALTER TABLE chronicle_events ADD COLUMN actors TEXT;
ALTER TABLE chronicle_events ADD COLUMN action TEXT;
ALTER TABLE chronicle_events ADD COLUMN context_data TEXT;
ALTER TABLE chronicle_events ADD COLUMN causality TEXT;
ALTER TABLE chronicle_events ADD COLUMN valence TEXT;
ALTER TABLE chronicle_events ADD COLUMN modality TEXT DEFAULT 'ACTUAL';
-- Set default DATETIME for existing events (use created_at)
UPDATE chronicle_events
SET timestamp_iso8601 = created_at
WHERE timestamp_iso8601 IS NULL;

-- Make timestamp_iso8601 NOT NULL after setting defaults
-- SQLite Note: Making timestamp_iso8601 NOT NULL requires table recreation - defer to fix_nullable_columns.py
-- ALTER TABLE chronicle_events ALTER COLUMN timestamp_iso8601 SET NOT NULL;

-- Set default modality for existing events
UPDATE chronicle_events
SET modality = 'ACTUAL'
WHERE modality IS NULL;

-- Create indexes for improved query performance (without CONCURRENTLY for migration)
CREATE INDEX IF NOT EXISTS idx_chronicle_events_timestamp
ON chronicle_events (timestamp_iso8601);

CREATE INDEX IF NOT EXISTS idx_chronicle_events_action
ON chronicle_events (action);

-- SQLite Note: GIN indexes are PostgreSQL-specific, using standard B-tree indexes instead
CREATE INDEX IF NOT EXISTS idx_chronicle_events_actors
ON chronicle_events (actors);

CREATE INDEX IF NOT EXISTS idx_chronicle_events_causality
ON chronicle_events (causality);

CREATE INDEX IF NOT EXISTS idx_chronicle_events_modality
ON chronicle_events (modality);

-- Create a composite index for de-duplication queries
CREATE INDEX IF NOT EXISTS idx_chronicle_events_dedup
ON chronicle_events (action, chronicle_id, user_id, timestamp_iso8601);
