-- Create chronicle processing jobs table for Phase 5 distributed backfill system
CREATE TYPE chronicle_job_status AS ENUM ('pending', 'in_progress', 'completed', 'failed', 'dead_letter');

CREATE TABLE chronicle_processing_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    chronicle_id UUID NOT NULL REFERENCES player_chronicles(id) ON DELETE CASCADE,
    
    -- Job management
    status chronicle_job_status NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 0, -- Higher number = higher priority
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    
    -- Timing
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    next_retry_at TIMESTAMPTZ,
    
    -- Processing details
    worker_id UUID, -- ID of worker currently processing this job
    processing_metadata JSONB DEFAULT '{}',
    
    -- Error handling
    last_error TEXT,
    error_details JSONB,
    
    -- Checksum for validation (Phase 5.1.2)
    chronicle_events_hash TEXT, -- Hash of all events for this chronicle
    ecs_state_checksum TEXT, -- Checksum of resulting ECS state
    
    -- Performance tracking
    events_processed INTEGER DEFAULT 0,
    entities_created INTEGER DEFAULT 0,
    components_created INTEGER DEFAULT 0,
    relationships_created INTEGER DEFAULT 0,
    processing_duration_ms BIGINT,
    
    -- Constraints
    UNIQUE(user_id, chronicle_id)
);

-- Indexes for efficient job queue operations
CREATE INDEX idx_chronicle_jobs_status_priority ON chronicle_processing_jobs(status, priority DESC, created_at ASC);
CREATE INDEX idx_chronicle_jobs_user_id ON chronicle_processing_jobs(user_id);
CREATE INDEX idx_chronicle_jobs_worker ON chronicle_processing_jobs(worker_id) WHERE worker_id IS NOT NULL;
CREATE INDEX idx_chronicle_jobs_retry ON chronicle_processing_jobs(status, next_retry_at) WHERE status = 'failed';
CREATE INDEX idx_chronicle_jobs_completed ON chronicle_processing_jobs(completed_at) WHERE status = 'completed';

-- Comments for documentation
COMMENT ON TABLE chronicle_processing_jobs IS 'Job queue for distributed chronicle-to-ECS processing in Phase 5';
COMMENT ON COLUMN chronicle_processing_jobs.priority IS 'Higher number = higher priority. 0=normal, 100=high, 1000=critical';
COMMENT ON COLUMN chronicle_processing_jobs.chronicle_events_hash IS 'SHA-256 hash of all chronicle events for determinism validation';
COMMENT ON COLUMN chronicle_processing_jobs.ecs_state_checksum IS 'SHA-256 checksum of resulting ECS state for validation';