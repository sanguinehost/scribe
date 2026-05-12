-- up.sql
CREATE TABLE IF NOT EXISTS cognitive_facts (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    chronicle_id UUID NOT NULL,
    -- 5D Facts (Encrypted)
    who_encrypted BYTEA NOT NULL,
    who_nonce BYTEA NOT NULL,
    what_encrypted BYTEA NOT NULL,
    what_nonce BYTEA NOT NULL,
    where_encrypted BYTEA NOT NULL,
    where_nonce BYTEA NOT NULL,
    when_encrypted BYTEA NOT NULL,
    when_nonce BYTEA NOT NULL,
    why_encrypted BYTEA NOT NULL,
    why_nonce BYTEA NOT NULL,
    -- Metadata
    fact_type TEXT NOT NULL, -- world, experience, opinion, observation
    confidence REAL NOT NULL,
    significance REAL NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cognitive_facts_user_chronicle ON cognitive_facts(user_id, chronicle_id);

CREATE TABLE IF NOT EXISTS cognitive_core_memory (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    chronicle_id UUID NOT NULL,
    memory_state_encrypted BYTEA NOT NULL,
    memory_state_nonce BYTEA NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cognitive_core_memory_user_chronicle ON cognitive_core_memory(user_id, chronicle_id);
