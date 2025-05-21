-- Your SQL goes here
CREATE TABLE user_personas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR NOT NULL,
    description BYTEA NOT NULL, -- Encrypted
    spec VARCHAR,
    spec_version VARCHAR,
    personality BYTEA,          -- Encrypted
    scenario BYTEA,             -- Encrypted
    first_mes BYTEA,            -- Encrypted
    mes_example BYTEA,          -- Encrypted
    system_prompt BYTEA,        -- Encrypted
    post_history_instructions BYTEA, -- Encrypted
    tags TEXT[],
    avatar VARCHAR,
    description_nonce BYTEA,
    personality_nonce BYTEA,
    scenario_nonce BYTEA,
    first_mes_nonce BYTEA,
    mes_example_nonce BYTEA,
    system_prompt_nonce BYTEA,
    post_history_instructions_nonce BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Trigger to update 'updated_at' timestamp
CREATE TRIGGER set_timestamp_user_personas
BEFORE UPDATE ON user_personas
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

-- Indexes
CREATE INDEX idx_user_personas_on_user_id ON user_personas(user_id);
