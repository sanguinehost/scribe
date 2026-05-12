-- up.sql
CREATE TABLE IF NOT EXISTS character_opinions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    chronicle_id TEXT NOT NULL,
    perspective_hash TEXT NOT NULL, -- Blind Index (HMAC)
    perspective_encrypted BLOB NOT NULL,
    perspective_nonce BLOB NOT NULL,
    opinion_encrypted BLOB NOT NULL,
    opinion_nonce BLOB NOT NULL,
    confidence REAL NOT NULL,
    significance REAL NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_character_opinions_user_chronicle ON character_opinions(user_id, chronicle_id);
CREATE INDEX IF NOT EXISTS idx_character_opinions_perspective_hash ON character_opinions(perspective_hash);

CREATE TABLE IF NOT EXISTS entity_observations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    chronicle_id TEXT NOT NULL,
    entity_name_hash TEXT NOT NULL, -- Blind Index (HMAC)
    entity_name_encrypted BLOB NOT NULL,
    entity_name_nonce BLOB NOT NULL,
    observation_encrypted BLOB NOT NULL,
    observation_nonce BLOB NOT NULL,
    confidence REAL NOT NULL,
    significance REAL NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_entity_observations_user_chronicle ON entity_observations(user_id, chronicle_id);
CREATE INDEX IF NOT EXISTS idx_entity_observations_entity_name_hash ON entity_observations(entity_name_hash);
