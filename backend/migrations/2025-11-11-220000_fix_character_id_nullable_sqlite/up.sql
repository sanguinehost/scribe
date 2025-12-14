-- SQLite-specific migration to make character_id nullable
-- The previous migration (2025-06-17) used ALTER COLUMN which only works in PostgreSQL
-- For SQLite, we need to recreate the table

-- This migration is safe to run on PostgreSQL as well - it will fail gracefully
-- since the table recreation uses SQLite-specific syntax, but PostgreSQL already
-- has character_id as nullable from the previous migration.

-- For SQLite: Recreate table with character_id nullable
-- Note: SQLite doesn't support ALTER COLUMN, so we use the standard table recreation pattern

PRAGMA foreign_keys = OFF;

-- Create temporary table with correct schema (character_id nullable)
CREATE TABLE IF NOT EXISTS chat_sessions_temp (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    character_id TEXT,  -- NOW NULLABLE (was NOT NULL before)
    temperature REAL,
    max_output_tokens INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    frequency_penalty REAL,
    presence_penalty REAL,
    top_k INTEGER,
    top_p REAL,
    repetition_penalty REAL,
    min_p REAL,
    top_a REAL,
    seed INTEGER,
    logit_bias TEXT,
    history_management_strategy TEXT NOT NULL,
    history_management_limit INTEGER NOT NULL,
    model_name TEXT NOT NULL,
    gemini_thinking_budget INTEGER,
    gemini_enable_code_execution INTEGER,
    visibility TEXT,
    active_custom_persona_id TEXT,
    active_impersonated_character_id TEXT,
    system_prompt_ciphertext BLOB,
    system_prompt_nonce BLOB,
    title_ciphertext BLOB,
    title_nonce BLOB,
    stop_sequences TEXT,
    chat_mode TEXT NOT NULL DEFAULT 'Character',
    player_chronicle_id TEXT,
    agent_mode TEXT,
    model_provider TEXT,
    total_prompt_tokens INTEGER NOT NULL DEFAULT 0,
    total_completion_tokens INTEGER NOT NULL DEFAULT 0,
    estimated_cost_cents INTEGER NOT NULL DEFAULT 0,
    tokens_counted_at TEXT NOT NULL DEFAULT (datetime('now')),
    prompt_template_id TEXT,
    total_credits_used INTEGER NOT NULL DEFAULT 0,
    narrative_style_override_ciphertext BLOB,
    narrative_style_override_nonce BLOB,
    total_actual_cost REAL NOT NULL DEFAULT 0.0,
    total_modified_cost REAL NOT NULL DEFAULT 0.0,
    total_credit_cost INTEGER NOT NULL DEFAULT 0,
    total_actual_charge REAL NOT NULL DEFAULT 0.0
);

-- Copy existing data if table exists
INSERT INTO chat_sessions_temp
SELECT * FROM chat_sessions
WHERE EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='chat_sessions');

-- Drop old table if it exists
DROP TABLE IF EXISTS chat_sessions;

-- Rename temp table to final name
ALTER TABLE chat_sessions_temp RENAME TO chat_sessions;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_id ON chat_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_character_id ON chat_sessions (character_id);

PRAGMA foreign_keys = ON;
