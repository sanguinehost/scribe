-- Create ECS entities table
-- Task 1.1.1: Create ecs_entities table migration with proper indexes and rollback capability

-- Create ecs_entities table
CREATE TABLE ecs_entities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    archetype_signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_ecs_entities_archetype_signature ON ecs_entities(archetype_signature);
CREATE INDEX idx_ecs_entities_created_at ON ecs_entities(created_at);
CREATE INDEX idx_ecs_entities_updated_at ON ecs_entities(updated_at);

-- Create function to auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_ecs_entities_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to auto-update updated_at on updates
CREATE TRIGGER trigger_ecs_entities_updated_at
    BEFORE UPDATE ON ecs_entities
    FOR EACH ROW
    EXECUTE FUNCTION update_ecs_entities_updated_at();