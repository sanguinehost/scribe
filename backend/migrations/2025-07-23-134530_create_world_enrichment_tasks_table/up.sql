-- Create world_enrichment_tasks table for Epic 8: Orchestrator-Driven Intelligent Agent System
-- This table provides durable task queue for background world enrichment processing

CREATE TABLE world_enrichment_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status INTEGER NOT NULL DEFAULT 0, -- 0=Pending, 1=InProgress, 2=Completed, 3=Failed
    priority INTEGER NOT NULL DEFAULT 2, -- 0=Critical, 1=High, 2=Normal, 3=Low
    encrypted_payload BYTEA NOT NULL,
    payload_nonce BYTEA NOT NULL,
    encrypted_error BYTEA NULL,
    error_nonce BYTEA NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    worker_id UUID NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient task queue operations
CREATE INDEX idx_world_enrichment_tasks_status_priority_created 
ON world_enrichment_tasks(status, priority, created_at) 
WHERE status = 0; -- Only index pending tasks for dequeue performance

CREATE INDEX idx_world_enrichment_tasks_session_id 
ON world_enrichment_tasks(session_id);

CREATE INDEX idx_world_enrichment_tasks_user_id 
ON world_enrichment_tasks(user_id);

CREATE INDEX idx_world_enrichment_tasks_worker_id 
ON world_enrichment_tasks(worker_id) 
WHERE worker_id IS NOT NULL;

-- Index for cleanup operations (completed/failed tasks older than X)
CREATE INDEX idx_world_enrichment_tasks_cleanup 
ON world_enrichment_tasks(status, created_at) 
WHERE status IN (2, 3); -- Completed or Failed

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_world_enrichment_tasks_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
CREATE TRIGGER world_enrichment_tasks_updated_at_trigger
    BEFORE UPDATE ON world_enrichment_tasks
    FOR EACH ROW
    EXECUTE FUNCTION update_world_enrichment_tasks_updated_at();
