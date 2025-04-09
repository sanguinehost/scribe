-- This file was automatically created by Diesel to setup helper functions
-- and other internal bookkeeping. This file is safe to edit, any future
-- changes will be added to existing projects as new migrations.

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Define speaker type enum used in chat_messages
CREATE TYPE speaker_type AS ENUM ('user', 'ai');

-- Function to automatically update 'updated_at' timestamps
CREATE OR REPLACE FUNCTION diesel_manage_updated_at(_tbl regclass) RETURNS VOID AS $$
BEGIN
    EXECUTE format('CREATE TRIGGER set_updated_at BEFORE UPDATE ON %s
                    FOR EACH ROW EXECUTE PROCEDURE diesel_set_updated_at()', _tbl);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION diesel_set_updated_at() RETURNS trigger AS $$
BEGIN
    IF (
        NEW IS DISTINCT FROM OLD AND
        NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at
    ) THEN
        NEW.updated_at := NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Users table (matches models/users.rs)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT diesel_manage_updated_at('users');
CREATE INDEX idx_users_username ON users (username);

-- Characters table (matches updated models/character_card.rs Character struct)
CREATE TABLE characters (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), -- Matches updated model
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- Matches updated model
    spec VARCHAR(255) NOT NULL, -- Adjusted size, matches model
    spec_version VARCHAR(50) NOT NULL, -- Adjusted size, matches model
    name VARCHAR(255) NOT NULL, -- Matches model (Option<String> -> NOT NULL assumed essential)
    description TEXT, -- Matches model Option<String>
    personality TEXT, -- Matches model Option<String>
    scenario TEXT, -- Matches model Option<String>
    first_mes TEXT, -- Matches model Option<String>
    mes_example TEXT, -- Matches model Option<String>
    creator_notes TEXT, -- Matches model Option<String>
    system_prompt TEXT, -- Matches model Option<String>
    post_history_instructions TEXT, -- Matches model Option<String>
    tags TEXT[], -- Matches model Vec<Option<String>>
    creator VARCHAR(255), -- Matches model Option<String>
    character_version VARCHAR(255), -- Matches model Option<String>
    alternate_greetings TEXT[], -- Matches model Vec<Option<String>>
    nickname VARCHAR(255), -- Matches model Option<String>
    creator_notes_multilingual JSONB, -- Matches model Option<JsonValue>
    source TEXT[], -- Matches model Option<Vec<Option<String>>>
    group_only_greetings TEXT[], -- Matches model Option<Vec<Option<String>>>
    creation_date TIMESTAMPTZ, -- Matches model Option<DateTime<Utc>>
    modification_date TIMESTAMPTZ, -- Matches model Option<DateTime<Utc>>
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- Matches model Option<DateTime<Utc>> -> Defaulted NOT NULL
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW() -- Matches model Option<DateTime<Utc>> -> Defaulted NOT NULL
);
SELECT diesel_manage_updated_at('characters');
CREATE INDEX idx_characters_user_id ON characters (user_id);

-- Character Assets table (matches updated models/character_card.rs CharacterAsset struct)
CREATE TABLE character_assets (
    id SERIAL PRIMARY KEY, -- Matches model i32
    character_id UUID NOT NULL REFERENCES characters(id) ON DELETE CASCADE, -- Matches updated model Uuid
    asset_type VARCHAR(50) NOT NULL, -- Renamed from 'type_' in model, adjusted size
    uri TEXT NOT NULL, -- Matches model String
    name VARCHAR(255) NOT NULL, -- Matches model String
    ext VARCHAR(50) NOT NULL, -- Matches model String, adjusted size
    -- Adding standard timestamps, assuming they are desired though not in model struct
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- SELECT diesel_manage_updated_at('character_assets'); -- No updated_at in model, comment out trigger

-- Lorebooks table (matches updated models/character_card.rs DbLorebook struct)
CREATE TABLE lorebooks (
    id SERIAL PRIMARY KEY, -- Matches model i32
    character_id UUID NOT NULL REFERENCES characters(id) ON DELETE CASCADE, -- Matches updated model Uuid
    name VARCHAR(255), -- Matches model Option<String>
    description TEXT, -- Matches model Option<String>
    scan_depth INTEGER, -- Matches model Option<i32>
    token_budget INTEGER, -- Matches model Option<i32>
    recursive_scanning BOOLEAN, -- Matches model Option<bool>
    extensions JSONB, -- Matches model Option<JsonValue>
    -- Adding standard timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT diesel_manage_updated_at('lorebooks');

-- Lorebook Entries table (matches models/character_card.rs DbLorebookEntry struct)
CREATE TABLE lorebook_entries (
    id SERIAL PRIMARY KEY, -- Matches model i32
    lorebook_id INTEGER NOT NULL REFERENCES lorebooks(id) ON DELETE CASCADE, -- Matches model i32
    keys TEXT[] NOT NULL, -- Matches model Vec<Option<String>>
    content TEXT NOT NULL, -- Matches model String
    extensions JSONB, -- Matches model Option<JsonValue>
    enabled BOOLEAN NOT NULL, -- Matches model bool
    insertion_order INTEGER NOT NULL, -- Matches model i32
    case_sensitive BOOLEAN, -- Matches model Option<bool>
    use_regex BOOLEAN NOT NULL, -- Matches model bool
    constant BOOLEAN, -- Matches model Option<bool>
    name VARCHAR(255), -- Matches model Option<String>
    priority INTEGER, -- Matches model Option<i32>
    entry_id VARCHAR(255), -- Matches model Option<String>
    comment TEXT, -- Matches model Option<String>
    selective BOOLEAN, -- Matches model Option<bool>
    secondary_keys TEXT[], -- Matches model Option<Vec<Option<String>>>
    position VARCHAR(50), -- Matches model Option<String>, adjusted size
    -- Adding standard timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT diesel_manage_updated_at('lorebook_entries');
CREATE INDEX idx_lorebook_entries_lorebook_id ON lorebook_entries (lorebook_id);

-- Chat Sessions table (Inferred structure)
CREATE TABLE chat_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    character_id UUID NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
    title VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT diesel_manage_updated_at('chat_sessions');
CREATE INDEX idx_chat_sessions_user_id ON chat_sessions (user_id);
CREATE INDEX idx_chat_sessions_character_id ON chat_sessions (character_id);

-- Chat Messages table (Inferred structure)
CREATE TABLE chat_messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    speaker speaker_type NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_chat_messages_session_id_created_at ON chat_messages (session_id, created_at);
