-- Simplify chronicle events to text summaries with keywords
-- Add new fields
ALTER TABLE chronicle_events 
    ADD COLUMN IF NOT EXISTS keywords TEXT[] DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS keywords_encrypted BYTEA,
    ADD COLUMN IF NOT EXISTS keywords_nonce BYTEA,
    ADD COLUMN IF NOT EXISTS chat_session_id UUID REFERENCES chat_sessions(id);

-- Drop complex Ars Fabula fields that are no longer needed
ALTER TABLE chronicle_events
    DROP COLUMN IF EXISTS actors,
    DROP COLUMN IF EXISTS action,
    DROP COLUMN IF EXISTS context_data,
    DROP COLUMN IF EXISTS causality,
    DROP COLUMN IF EXISTS valence,
    DROP COLUMN IF EXISTS modality,
    DROP COLUMN IF EXISTS event_data;

-- The event_type column can be simplified too since we don't need complex categorization
-- We'll keep it for now but it can just be 'USER_CREATED' or 'AI_EXTRACTED'
