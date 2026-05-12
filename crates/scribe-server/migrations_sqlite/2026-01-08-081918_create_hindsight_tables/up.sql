-- up.sql
CREATE TABLE IF NOT EXISTS cognitive_facts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    chronicle_id TEXT NOT NULL,
    -- 5D Facts (Encrypted)
    who_encrypted BLOB NOT NULL,
    who_nonce BLOB NOT NULL,
    what_encrypted BLOB NOT NULL,
    what_nonce BLOB NOT NULL,
    where_encrypted BLOB NOT NULL,
    where_nonce BLOB NOT NULL,
    when_encrypted BLOB NOT NULL,
    when_nonce BLOB NOT NULL,
    why_encrypted BLOB NOT NULL,
    why_nonce BLOB NOT NULL,
    -- Metadata
    fact_type TEXT NOT NULL, -- world, experience, opinion, observation
    confidence REAL NOT NULL,
    significance REAL NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cognitive_facts_user_chronicle ON cognitive_facts(user_id, chronicle_id);

CREATE TABLE IF NOT EXISTS cognitive_core_memory (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    chronicle_id TEXT NOT NULL,
    memory_state_encrypted BLOB NOT NULL,
    memory_state_nonce BLOB NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cognitive_core_memory_user_chronicle ON cognitive_core_memory(user_id, chronicle_id);
