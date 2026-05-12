-- Your SQL goes here

CREATE TABLE IF NOT EXISTS chat_character_overrides (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    chat_session_id UUID NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    original_character_id UUID NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
    field_name VARCHAR(255) NOT NULL,
    overridden_value BYTEA NOT NULL,
    overridden_value_nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_chat_character_override UNIQUE (chat_session_id, original_character_id, field_name)
);

-- Create a trigger to automatically update updated_at
-- Attempt to drop trigger first to make it idempotent, then create.
DROP TRIGGER IF EXISTS set_timestamp_chat_character_overrides ON chat_character_overrides;
CREATE TRIGGER set_timestamp_chat_character_overrides
BEFORE UPDATE ON chat_character_overrides
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();
