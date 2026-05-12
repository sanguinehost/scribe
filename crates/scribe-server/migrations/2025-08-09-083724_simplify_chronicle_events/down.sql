-- Revert chronicle events to complex structure
-- Note: This is destructive as we can't recover the complex data once deleted

-- Re-add complex fields (they will be NULL for existing records)
ALTER TABLE chronicle_events
    ADD COLUMN IF NOT EXISTS actors JSONB,
    ADD COLUMN IF NOT EXISTS action VARCHAR(100),
    ADD COLUMN IF NOT EXISTS context_data JSONB,
    ADD COLUMN IF NOT EXISTS causality JSONB,
    ADD COLUMN IF NOT EXISTS valence JSONB,
    ADD COLUMN IF NOT EXISTS modality VARCHAR(50),
    ADD COLUMN IF NOT EXISTS event_data JSONB;

-- Drop simplified fields
ALTER TABLE chronicle_events
    DROP COLUMN IF EXISTS keywords,
    DROP COLUMN IF EXISTS keywords_encrypted,
    DROP COLUMN IF EXISTS keywords_nonce,
    DROP COLUMN IF EXISTS chat_session_id;
