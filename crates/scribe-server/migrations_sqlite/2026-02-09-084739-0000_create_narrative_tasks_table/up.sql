-- up.sql
CREATE TABLE IF NOT EXISTS narrative_tasks (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    workflow_type TEXT NOT NULL,
    current_state BLOB NOT NULL, -- Encrypted DurableWorkflow state
    status TEXT NOT NULL,        -- 'pending', 'processing', 'completed', 'failed'
    worker_id TEXT,              -- ID of the worker currently claiming the task
    trace_context TEXT,          -- Serialized W3C Trace Context
    expires_at DATETIME NOT NULL, -- Heartbeat timeout
    last_step_at DATETIME NOT NULL, -- Last successful transition
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS update_narrative_tasks_timestamp
AFTER UPDATE ON narrative_tasks
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE narrative_tasks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE INDEX IF NOT EXISTS idx_narrative_tasks_status_expires ON narrative_tasks(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_narrative_tasks_session ON narrative_tasks(session_id);
CREATE INDEX IF NOT EXISTS idx_narrative_tasks_user ON narrative_tasks(user_id);
