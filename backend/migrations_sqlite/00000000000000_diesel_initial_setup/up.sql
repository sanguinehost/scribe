-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.485837
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- This file was automatically created by Diesel to setup helper functions
-- and other internal bookkeeping. This file is safe to edit, any future
-- changes will be added to existing projects as new migrations.

-- Enable TEXT generation
-- CREATE EXTENSION IF NOT EXISTS "TEXT-ossp"; -- Removed: SQLite does not support extensions

-- Drop dependent objects first if they exist (idempotent)
-- Note: Order matters. Drop table before type.
DROP TABLE IF EXISTS chat_messages;
DROP TYPE IF EXISTS TEXT;

-- Define message type enum using standard roles
-- CREATE TYPE TEXT -- Removed: SQLite uses TEXT for enums -- Changed 'Ai' to 'Assistant', added 'System'

-- Function to automatically update 'updated_at' timestamps
-- CREATE OR REPLACE FUNCTION diesel_manage_updated_at(_tbl regclass) RETURNS VOID AS $$
BEGIN
    EXEC... -- Removed: SQLite does not support PL/pgSQL

-- CREATE OR REPLACE FUNCTION diesel_set_updated_at() RETURNS trigger AS $$
BEGIN
    IF (
        NEW ... -- Removed: SQLite does not support PL/pgSQL

-- Users table (matches models/users.rs)
CREATE TABLE users (
    id TEXT PRIMARY KEY ,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- SQLite trigger for updating timestamps on users
CREATE TRIGGER IF NOT EXISTS update_users_timestamp
AFTER UPDATE ON users
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
CREATE INDEX idx_users_username ON users (username);

-- Characters table (matches updated models/character_card.rs Character struct)
CREATE TABLE characters (
    id TEXT PRIMARY KEY , -- Matches updated model
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- Matches updated model
    spec TEXT NOT NULL, -- Adjusted size, matches model
    spec_version TEXT NOT NULL, -- Adjusted size, matches model
    name TEXT NOT NULL, -- Matches model (Option<String> -> NOT NULL assumed essential)
    description TEXT, -- Matches model Option<String>
    personality TEXT, -- Matches model Option<String>
    scenario TEXT, -- Matches model Option<String>
    first_mes TEXT, -- Matches model Option<String>
    mes_example TEXT, -- Matches model Option<String>
    creator_notes TEXT, -- Matches model Option<String>
    system_prompt TEXT, -- Matches model Option<String>
    post_history_instructions TEXT, -- Matches model Option<String>
    tags TEXT, -- Matches model Vec<Option<String>>
    creator TEXT, -- Matches model Option<String>
    character_version TEXT, -- Matches model Option<String>
    alternate_greetings TEXT, -- Matches model Vec<Option<String>>
    nickname TEXT, -- Matches model Option<String>
    creator_notes_multilingual TEXT, -- Matches model Option<JsonValue>
    source TEXT, -- Matches model Option<Vec<Option<String>>>
    group_only_greetings TEXT, -- Matches model Option<Vec<Option<String>>>
    creation_date DATETIME, -- Matches model Option<DateTime<Utc>>
    modification_date DATETIME, -- Matches model Option<DateTime<Utc>>
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- Matches model Option<DateTime<Utc>> -> Defaulted NOT NULL
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP -- Matches model Option<DateTime<Utc>> -> Defaulted NOT NULL
);

-- SQLite trigger for updating timestamps on characters
CREATE TRIGGER IF NOT EXISTS update_characters_timestamp
AFTER UPDATE ON characters
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE characters SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
CREATE INDEX idx_characters_user_id ON characters (user_id);

-- Character Assets table (matches updated models/character_card.rs CharacterAsset struct)
CREATE TABLE character_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- Matches model i32
    character_id TEXT NOT NULL REFERENCES characters(id) ON DELETE CASCADE, -- Matches updated model TEXT
    asset_type TEXT NOT NULL, -- Renamed from 'type_' in model, adjusted size
    uri TEXT NOT NULL, -- Matches model String
    name TEXT NOT NULL, -- Matches model String
    ext TEXT NOT NULL, -- Matches model String, adjusted size
    -- Adding standard timestamps, assuming they are desired though not in model struct
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--
-- SQLite trigger for updating timestamps on character_assets
CREATE TRIGGER IF NOT EXISTS update_character_assets_timestamp
AFTER UPDATE ON character_assets
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE character_assets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END; -- No updated_at in model, comment out trigger

-- Lorebooks table (matches updated models/character_card.rs DbLorebook struct)
CREATE TABLE lorebooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- Matches model i32
    character_id TEXT NOT NULL REFERENCES characters(id) ON DELETE CASCADE, -- Matches updated model TEXT
    name TEXT, -- Matches model Option<String>
    description TEXT, -- Matches model Option<String>
    scan_depth INTEGER, -- Matches model Option<i32>
    token_budget INTEGER, -- Matches model Option<i32>
    recursive_scanning BOOLEAN, -- Matches model Option<bool>
    extensions TEXT, -- Matches model Option<JsonValue>
    -- Adding standard timestamps
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- SQLite trigger for updating timestamps on lorebooks
CREATE TRIGGER IF NOT EXISTS update_lorebooks_timestamp
AFTER UPDATE ON lorebooks
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE lorebooks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Lorebook Entries table (matches models/character_card.rs DbLorebookEntry struct)
CREATE TABLE lorebook_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- Matches model i32
    lorebook_id INTEGER NOT NULL REFERENCES lorebooks(id) ON DELETE CASCADE, -- Matches model i32
    keys TEXT NOT NULL, -- Matches model Vec<Option<String>>
    content TEXT NOT NULL, -- Matches model String
    extensions TEXT, -- Matches model Option<JsonValue>
    enabled BOOLEAN NOT NULL, -- Matches model bool
    insertion_order INTEGER NOT NULL, -- Matches model i32
    case_sensitive BOOLEAN, -- Matches model Option<bool>
    use_regex BOOLEAN NOT NULL, -- Matches model bool
    constant BOOLEAN, -- Matches model Option<bool>
    name TEXT, -- Matches model Option<String>
    priority INTEGER, -- Matches model Option<i32>
    entry_id TEXT, -- Matches model Option<String>
    comment TEXT, -- Matches model Option<String>
    selective BOOLEAN, -- Matches model Option<bool>
    secondary_keys TEXT, -- Matches model Option<Vec<Option<String>>>
    position TEXT, -- Matches model Option<String>, adjusted size
    -- Adding standard timestamps
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- SQLite trigger for updating timestamps on lorebook_entries
CREATE TRIGGER IF NOT EXISTS update_lorebook_entries_timestamp
AFTER UPDATE ON lorebook_entries
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE lorebook_entries SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
CREATE INDEX idx_lorebook_entries_lorebook_id ON lorebook_entries (lorebook_id);

-- Chat Sessions table (Inferred structure)
CREATE TABLE chat_sessions (
    id TEXT PRIMARY KEY ,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    character_id TEXT NOT NULL REFERENCES characters(id) ON DELETE CASCADE,
    title TEXT, -- Added based on potential need, nullable
    system_prompt TEXT, -- Added to match model Option<String>
    temperature NUMERIC, -- Added to match model Option<f64>, use NUMERIC for precision
    max_output_tokens INTEGER, -- Added to match model Option<i32>
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- SQLite trigger for updating timestamps on chat_sessions
CREATE TRIGGER IF NOT EXISTS update_chat_sessions_timestamp
AFTER UPDATE ON chat_sessions
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE chat_sessions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
CREATE INDEX idx_chat_sessions_user_id ON chat_sessions (user_id);
CREATE INDEX idx_chat_sessions_character_id ON chat_sessions (character_id);

-- Recreate Chat Messages table (using the corrected TEXT)
CREATE TABLE chat_messages (
    id TEXT PRIMARY KEY ,
    session_id TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    TEXT TEXT NOT NULL, -- Uses corrected type
    content TEXT NOT NULL,
    rag_embedding_id TEXT NULL, -- Added to match model Option<TEXT>, nullable
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP -- Added to match model
);

-- SQLite trigger for updating timestamps on chat_messages
CREATE TRIGGER IF NOT EXISTS update_chat_messages_timestamp
AFTER UPDATE ON chat_messages
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE chat_messages SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END; -- Apply updated_at trigger
CREATE INDEX idx_chat_messages_session_id_created_at ON chat_messages (session_id, created_at);
