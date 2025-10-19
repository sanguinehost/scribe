-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.501097
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Create user_settings table for storing per-user default settings
CREATE TABLE user_settings (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Generation Settings (nullable - fall back to system defaults if not set)
    default_model_name TEXT,
    default_temperature DECIMAL(3,2),
    default_max_output_tokens INTEGER,
    default_frequency_penalty DECIMAL(3,2),
    default_presence_penalty DECIMAL(3,2),
    default_top_p DECIMAL(4,3),
    default_top_k INTEGER,
    default_seed INTEGER,

    -- Gemini-Specific Settings
    default_gemini_thinking_budget INTEGER,
    default_gemini_enable_code_execution BOOLEAN,

    -- Context Management Settings
    default_context_total_token_limit INTEGER,
    default_context_recent_history_budget INTEGER,
    default_context_rag_budget INTEGER,

    -- Application Preferences
    auto_save_chats BOOLEAN DEFAULT true,
    theme TEXT DEFAULT 'system',
    notifications_enabled BOOLEAN DEFAULT true,

    -- Timestamps
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Ensure one settings record per user
    UNIQUE(user_id)
);

-- Create index for faster lookups
CREATE INDEX idx_user_settings_user_id ON user_settings(user_id);

-- Create trigger to update updated_at DATETIME
-- CREATE OR REPLACE FUNCTION update_user_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.upd... -- Removed: SQLite does not support PL/pgSQL


-- SQLite trigger for updating timestamps on user_settings
CREATE TRIGGER IF NOT EXISTS update_user_settings_timestamp
AFTER UPDATE ON user_settings
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE user_settings SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
