-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.503261
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Revert chronicle events to complex structure
-- Note: This is destructive as we can't recover the complex data once deleted

-- Re-add complex fields (they will be NULL for existing records)
ALTER TABLE chronicle_events
    ADD COLUMN IF NOT EXISTS actors TEXT,
    ADD COLUMN IF NOT EXISTS action TEXT,
    ADD COLUMN IF NOT EXISTS context_data TEXT,
    ADD COLUMN IF NOT EXISTS causality TEXT,
    ADD COLUMN IF NOT EXISTS valence TEXT,
    ADD COLUMN IF NOT EXISTS modality TEXT,
    ADD COLUMN IF NOT EXISTS event_data TEXT;

-- Drop simplified fields
ALTER TABLE chronicle_events
    DROP COLUMN IF EXISTS keywords,
    DROP COLUMN IF EXISTS keywords_encrypted,
    DROP COLUMN IF EXISTS keywords_nonce,
    DROP COLUMN IF EXISTS chat_session_id;
