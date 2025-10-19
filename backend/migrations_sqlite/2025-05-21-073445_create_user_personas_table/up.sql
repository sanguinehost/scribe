-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.492236
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here
CREATE TABLE user_personas (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR NOT NULL,
    description BLOB NOT NULL, -- Encrypted
    spec VARCHAR,
    spec_version VARCHAR,
    personality BLOB,          -- Encrypted
    scenario BLOB,             -- Encrypted
    first_mes BLOB,            -- Encrypted
    mes_example BLOB,          -- Encrypted
    system_prompt BLOB,        -- Encrypted
    post_history_instructions BLOB, -- Encrypted
    tags TEXT,
    avatar VARCHAR,
    description_nonce BLOB,
    personality_nonce BLOB,
    scenario_nonce BLOB,
    first_mes_nonce BLOB,
    mes_example_nonce BLOB,
    system_prompt_nonce BLOB,
    post_history_instructions_nonce BLOB,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Trigger to update 'updated_at' DATETIME
CREATE TRIGGER set_timestamp_user_personas
BEFORE UPDATE ON user_personas
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

-- Indexes
CREATE INDEX idx_user_personas_on_user_id ON user_personas(user_id);
