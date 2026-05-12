-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.503063
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Simplify chronicle events to text summaries with keywords
-- Add new fields
-- Note: SQLite doesn't support IF NOT EXISTS in ALTER TABLE ADD COLUMN (before 3.35.0)
-- Since migrations run in sequence, columns shouldn't exist yet, so this is safe


ALTER TABLE chronicle_events ADD COLUMN keywords TEXT DEFAULT '{}';
ALTER TABLE chronicle_events ADD COLUMN keywords_encrypted BLOB;
ALTER TABLE chronicle_events ADD COLUMN keywords_nonce BLOB;
ALTER TABLE chronicle_events ADD COLUMN chat_session_id TEXT REFERENCES chat_sessions(id);

-- Drop indexes on columns before dropping the columns
DROP INDEX IF EXISTS idx_chronicle_events_actors;
DROP INDEX IF EXISTS idx_chronicle_events_action;
DROP INDEX IF EXISTS idx_chronicle_events_causality;
DROP INDEX IF EXISTS idx_chronicle_events_modality;
DROP INDEX IF EXISTS idx_chronicle_events_dedup; -- Composite index includes action column

-- Drop complex Ars Fabula fields that are no longer needed
-- SQLite Note: Each DROP COLUMN must be separate, and IF EXISTS is not supported
ALTER TABLE chronicle_events DROP COLUMN actors;
ALTER TABLE chronicle_events DROP COLUMN action;
ALTER TABLE chronicle_events DROP COLUMN context_data;
ALTER TABLE chronicle_events DROP COLUMN causality;
ALTER TABLE chronicle_events DROP COLUMN valence;
ALTER TABLE chronicle_events DROP COLUMN modality;
-- Note: event_data may not exist in all schemas, commenting out if it causes issues
-- ALTER TABLE chronicle_events DROP COLUMN event_data;

-- The event_type column can be simplified too since we don't need complex categorization
-- We'll keep it for now but it can just be 'USER_CREATED' or 'AI_EXTRACTED'
