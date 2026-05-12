-- SQLite Migration
-- Fix agent_context_analysis constraint by recreating the table

-- 1. Create new table without the strict UNIQUE(chat_session_id, analysis_type) constraint
CREATE TABLE new_agent_context_analysis (
    id TEXT PRIMARY KEY,
    chat_session_id TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id),
    analysis_type TEXT NOT NULL CHECK (analysis_type IN ('pre_processing', 'post_processing')),

    -- Agent thought process (encrypted)
    agent_reasoning TEXT,
    agent_reasoning_nonce BLOB,

    -- Planning phase - stores JSON array of planned searches
    planned_searches TEXT,

    -- Execution audit trail (encrypted) - full log of all tool calls and responses
    execution_log TEXT,
    execution_log_nonce BLOB,

    -- Final results (encrypted)
    retrieved_context TEXT,
    retrieved_context_nonce BLOB,
    analysis_summary TEXT,
    analysis_summary_nonce BLOB,

    -- Performance metrics
    total_tokens_used INTEGER,
    execution_time_ms INTEGER,
    model_used TEXT,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- New columns added in later migrations
    message_id TEXT NULL REFERENCES chat_messages(id) ON DELETE CASCADE,
    assistant_message_id TEXT REFERENCES chat_messages(id),
    status TEXT NOT NULL DEFAULT 'success',
    error_message TEXT,
    retry_count INT4 NOT NULL DEFAULT 0,
    superseded_at DATETIME
);

-- 2. Copy data from old table to new table
INSERT INTO new_agent_context_analysis (
    id, chat_session_id, user_id, analysis_type,
    agent_reasoning, agent_reasoning_nonce,
    planned_searches,
    execution_log, execution_log_nonce,
    retrieved_context, retrieved_context_nonce,
    analysis_summary, analysis_summary_nonce,
    total_tokens_used, execution_time_ms, model_used,
    created_at, updated_at,
    message_id, assistant_message_id, status, error_message, retry_count, superseded_at
)
SELECT
    id, chat_session_id, user_id, analysis_type,
    agent_reasoning, agent_reasoning_nonce,
    planned_searches,
    execution_log, execution_log_nonce,
    retrieved_context, retrieved_context_nonce,
    analysis_summary, analysis_summary_nonce,
    total_tokens_used, execution_time_ms, model_used,
    created_at, updated_at,
    message_id, assistant_message_id, status, error_message, retry_count, superseded_at
FROM agent_context_analysis;

-- 3. Drop old table
DROP TABLE agent_context_analysis;

-- 4. Rename new table to old table name
ALTER TABLE new_agent_context_analysis RENAME TO agent_context_analysis;

-- 5. Recreate indexes and triggers

-- Index for quick retrieval by session
CREATE INDEX idx_agent_context_session ON agent_context_analysis(chat_session_id);

-- Index for user's analyses
CREATE INDEX idx_agent_context_user ON agent_context_analysis(user_id);

-- Trigger for updating timestamps
CREATE TRIGGER update_agent_context_analysis_timestamp
AFTER UPDATE ON agent_context_analysis
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE agent_context_analysis SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Additional indexes from later migrations
CREATE INDEX idx_agent_context_analysis_session_message
ON agent_context_analysis(chat_session_id, message_id);

CREATE INDEX idx_agent_context_analysis_message
ON agent_context_analysis(message_id);

CREATE INDEX idx_agent_context_analysis_assistant_message_id
ON agent_context_analysis(assistant_message_id);

CREATE INDEX idx_agent_context_analysis_active
ON agent_context_analysis(chat_session_id, analysis_type, status)
WHERE superseded_at IS NULL;

-- The CORRECT unique constraint (per message, not per session)
CREATE UNIQUE INDEX idx_agent_context_analysis_unique_per_message
ON agent_context_analysis (chat_session_id, analysis_type, message_id)
WHERE message_id IS NOT NULL;
