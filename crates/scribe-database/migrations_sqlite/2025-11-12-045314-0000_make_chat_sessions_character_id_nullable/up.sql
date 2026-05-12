-- Make character_id nullable to support QuickStart and ScribeAssistant chat modes
-- SQLite doesn't support ALTER COLUMN, so we recreate the table
-- NOTE: Diesel wraps this in a transaction, so no explicit BEGIN/COMMIT

PRAGMA foreign_keys = OFF;

-- Create new table with character_id nullable
-- This uses the exact schema from 2025-06-17 migration (after chat_mode was added)
CREATE TABLE chat_sessions_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    character_id TEXT,  -- NOW NULLABLE (was NOT NULL)
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
    prompt_template_id TEXT DEFAULT 'neutral_roleplay',
    total_credits_used INTEGER NOT NULL DEFAULT 0,
    narrative_style_override_ciphertext BLOB,
    narrative_style_override_nonce BLOB,
    total_actual_cost REAL NOT NULL DEFAULT 0,
    total_modified_cost REAL NOT NULL DEFAULT 0,
    total_credit_cost INTEGER NOT NULL DEFAULT 0,
    total_actual_charge REAL NOT NULL DEFAULT 0
);

-- Copy all data (SELECT * works because column order matches)
INSERT INTO chat_sessions_new
SELECT * FROM chat_sessions;

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

PRAGMA foreign_keys = ON;
