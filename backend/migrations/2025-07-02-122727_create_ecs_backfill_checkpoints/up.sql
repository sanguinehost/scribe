-- Create table for tracking chronicle backfill progress with checkpointing
CREATE TABLE ecs_backfill_checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    chronicle_id UUID REFERENCES player_chronicles(id) ON DELETE CASCADE, -- NULL for global checkpoints
    last_processed_event_id UUID NOT NULL REFERENCES chronicle_events(id) ON DELETE CASCADE,
    last_processed_timestamp TIMESTAMPTZ NOT NULL,
    events_processed_count BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'IN_PROGRESS' CHECK (status IN ('IN_PROGRESS', 'COMPLETED', 'FAILED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for efficient querying
CREATE INDEX idx_ecs_backfill_checkpoints_user_id ON ecs_backfill_checkpoints(user_id);
CREATE INDEX idx_ecs_backfill_checkpoints_chronicle_id ON ecs_backfill_checkpoints(chronicle_id);
CREATE INDEX idx_ecs_backfill_checkpoints_status ON ecs_backfill_checkpoints(status);
CREATE INDEX idx_ecs_backfill_checkpoints_updated_at ON ecs_backfill_checkpoints(updated_at);

-- Unique constraint to prevent duplicate checkpoints per user/chronicle
CREATE UNIQUE INDEX idx_ecs_backfill_checkpoints_unique 
ON ecs_backfill_checkpoints(user_id, COALESCE(chronicle_id, '00000000-0000-0000-0000-000000000000'::UUID));

-- Trigger to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_ecs_backfill_checkpoints_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_ecs_backfill_checkpoints_updated_at
    BEFORE UPDATE ON ecs_backfill_checkpoints
    FOR EACH ROW
    EXECUTE FUNCTION update_ecs_backfill_checkpoints_updated_at();