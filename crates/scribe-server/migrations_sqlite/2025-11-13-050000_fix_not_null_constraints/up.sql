-- Fix NOT NULL constraints for prompt_template_id (chat_sessions), user_id and model_name (chat_messages)
-- SQLite doesn't support ALTER COLUMN, so we recreate the tables
-- NOTE: Diesel wraps this in a transaction, so no explicit BEGIN/COMMIT

PRAGMA foreign_keys = OFF;

-- ========================================
-- PART 1: Fix chat_sessions.prompt_template_id
-- ========================================

-- Update NULL values before recreating table
UPDATE chat_sessions SET prompt_template_id = 'neutral_roleplay' WHERE prompt_template_id IS NULL;

-- Create new chat_sessions table with prompt_template_id NOT NULL
CREATE TABLE chat_sessions_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    character_id TEXT,
    temperature NUMERIC,
    max_output_tokens INTEGER,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    frequency_penalty NUMERIC,
    presence_penalty NUMERIC,
    top_k INTEGER,
    top_p NUMERIC,
    repetition_penalty NUMERIC,
    min_p NUMERIC,
    top_a NUMERIC,
    seed INTEGER,
    logit_bias TEXT,
    history_management_strategy TEXT NOT NULL DEFAULT 'none',
    history_management_limit INTEGER NOT NULL DEFAULT 4096,
    model_name TEXT NOT NULL DEFAULT 'gemini-2.5-pro',
    gemini_thinking_budget INTEGER,
    gemini_enable_code_execution BOOLEAN,
    visibility TEXT DEFAULT 'private',
    active_custom_persona_id TEXT,
    active_impersonated_character_id TEXT,
    system_prompt_ciphertext BLOB,
    system_prompt_nonce BLOB,
    title_ciphertext BLOB,
    title_nonce BLOB,
    stop_sequences TEXT,
    chat_mode VARCHAR NOT NULL DEFAULT 'Character',
    player_chronicle_id TEXT,
    agent_mode TEXT DEFAULT 'disabled' CHECK (agent_mode IN ('disabled', 'pre_processing', 'post_processing')),
    model_provider TEXT,
    total_prompt_tokens INTEGER NOT NULL DEFAULT 0,
    total_completion_tokens INTEGER NOT NULL DEFAULT 0,
    estimated_cost_cents INTEGER NOT NULL DEFAULT 0,
    tokens_counted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    prompt_template_id TEXT NOT NULL DEFAULT 'neutral_roleplay',  -- NOW NOT NULL
    total_credits_used INTEGER NOT NULL DEFAULT 0,
    narrative_style_override_ciphertext BLOB,
    narrative_style_override_nonce BLOB,
    total_actual_cost REAL NOT NULL DEFAULT 0,
    total_modified_cost REAL NOT NULL DEFAULT 0,
    total_credit_cost INTEGER NOT NULL DEFAULT 0,
    total_actual_charge REAL NOT NULL DEFAULT 0
);

-- Copy all data
INSERT INTO chat_sessions_new SELECT * FROM chat_sessions;

-- Drop old table
DROP TABLE chat_sessions;

-- Rename new table
ALTER TABLE chat_sessions_new RENAME TO chat_sessions;

-- Recreate indexes
CREATE INDEX idx_chat_sessions_user_id ON chat_sessions (user_id);
CREATE INDEX idx_chat_sessions_character_id ON chat_sessions (character_id);
CREATE INDEX idx_chat_sessions_player_chronicle_id ON chat_sessions(player_chronicle_id);
CREATE INDEX idx_chat_sessions_agent_mode ON chat_sessions(agent_mode) WHERE agent_mode != 'disabled';
CREATE INDEX idx_chat_sessions_tokens_counted_at ON chat_sessions (tokens_counted_at);
CREATE INDEX idx_chat_sessions_with_narrative_override ON chat_sessions(id) WHERE narrative_style_override_ciphertext IS NOT NULL;

-- Recreate trigger
CREATE TRIGGER update_chat_sessions_timestamp
AFTER UPDATE ON chat_sessions
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE chat_sessions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- ========================================
-- PART 2: Fix chat_messages.user_id and model_name
-- ========================================

-- Update NULL values before recreating table (use placeholder values)
UPDATE chat_messages SET user_id = '00000000-0000-0000-0000-000000000000' WHERE user_id IS NULL;
UPDATE chat_messages SET model_name = 'unknown' WHERE model_name IS NULL;

-- Create new chat_messages table with user_id and model_name NOT NULL
CREATE TABLE chat_messages_new (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    message_type TEXT NOT NULL,
    content BLOB NOT NULL,
    rag_embedding_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id TEXT NOT NULL,  -- NOW NOT NULL
    content_nonce BLOB,
    role TEXT,
    parts TEXT,
    attachments TEXT,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    raw_prompt_ciphertext BLOB,
    raw_prompt_nonce BLOB,
    model_name TEXT NOT NULL,  -- NOW NOT NULL
    status TEXT NOT NULL,
    error_message TEXT,
    superseded_at DATETIME,
    variant_count INTEGER NOT NULL,
    current_variant_index INTEGER NOT NULL,
    credits_charged INTEGER NOT NULL,
    credits_cost INTEGER NOT NULL,
    actual_cost REAL NOT NULL,
    modified_cost REAL NOT NULL,
    credit_cost INTEGER NOT NULL,
    actual_charge REAL NOT NULL
);

-- Copy all data
INSERT INTO chat_messages_new SELECT * FROM chat_messages;

-- Drop old table
DROP TABLE chat_messages;

-- Rename new table
ALTER TABLE chat_messages_new RENAME TO chat_messages;

-- Recreate indexes
CREATE INDEX idx_chat_messages_session_id ON chat_messages (session_id);
CREATE INDEX idx_chat_messages_created_at ON chat_messages (created_at);
CREATE INDEX idx_chat_messages_status ON chat_messages (status);
CREATE INDEX idx_chat_messages_user_id ON chat_messages (user_id);

-- Recreate trigger
CREATE TRIGGER update_chat_messages_timestamp
AFTER UPDATE ON chat_messages
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE chat_messages SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

PRAGMA foreign_keys = ON;
