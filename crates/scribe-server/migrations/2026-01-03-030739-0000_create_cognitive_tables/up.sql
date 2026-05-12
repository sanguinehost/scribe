-- up.sql
CREATE TABLE IF NOT EXISTS character_opinions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    chronicle_id UUID NOT NULL,
    perspective_hash TEXT NOT NULL, -- Blind Index (HMAC)
    perspective_encrypted BYTEA NOT NULL,
    perspective_nonce BYTEA NOT NULL,
    opinion_encrypted BYTEA NOT NULL,
    opinion_nonce BYTEA NOT NULL,
    confidence REAL NOT NULL,
    significance REAL NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_character_opinions_user_chronicle ON character_opinions(user_id, chronicle_id);
CREATE INDEX IF NOT EXISTS idx_character_opinions_perspective_hash ON character_opinions(perspective_hash);

CREATE TABLE IF NOT EXISTS entity_observations (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    chronicle_id UUID NOT NULL,
    entity_name_hash TEXT NOT NULL, -- Blind Index (HMAC)
    entity_name_encrypted BYTEA NOT NULL,
    entity_name_nonce BYTEA NOT NULL,
    observation_encrypted BYTEA NOT NULL,
    observation_nonce BYTEA NOT NULL,
    confidence REAL NOT NULL,
    significance REAL NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_entity_observations_user_chronicle ON entity_observations(user_id, chronicle_id);
CREATE INDEX IF NOT EXISTS idx_entity_observations_entity_name_hash ON entity_observations(entity_name_hash);
