-- up.sql
CREATE TABLE IF NOT EXISTS narrative_tasks (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    session_id UUID NOT NULL,
    workflow_type TEXT NOT NULL,
    current_state BYTEA NOT NULL, -- Encrypted DurableWorkflow state
    status TEXT NOT NULL,         -- 'pending', 'processing', 'completed', 'failed'
    worker_id TEXT,               -- ID of the worker currently claiming the task
    trace_context TEXT,           -- Serialized W3C Trace Context
    expires_at TIMESTAMPTZ NOT NULL, -- Heartbeat timeout
    last_step_at TIMESTAMPTZ NOT NULL, -- Last successful transition
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_narrative_tasks_status_expires ON narrative_tasks(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_narrative_tasks_session ON narrative_tasks(session_id);
CREATE INDEX IF NOT EXISTS idx_narrative_tasks_user ON narrative_tasks(user_id);
