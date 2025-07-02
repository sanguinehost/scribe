-- Create ECS entity relationships table
-- Task 1.1.3: Create ecs_entity_relationships table for entity-to-entity relationships

-- Create ecs_entity_relationships table for directed relationships between entities
CREATE TABLE ecs_entity_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_entity_id UUID NOT NULL,
    to_entity_id UUID NOT NULL,
    relationship_type TEXT NOT NULL,
    relationship_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (from_entity_id) REFERENCES ecs_entities(id) ON DELETE CASCADE,
    FOREIGN KEY (to_entity_id) REFERENCES ecs_entities(id) ON DELETE CASCADE
);

-- Create unique constraint to prevent duplicate relationship types between same entities
CREATE UNIQUE INDEX idx_ecs_entity_relationships_unique 
ON ecs_entity_relationships(from_entity_id, to_entity_id, relationship_type);

-- Create indexes for performance
CREATE INDEX idx_ecs_entity_relationships_from_entity ON ecs_entity_relationships(from_entity_id);
CREATE INDEX idx_ecs_entity_relationships_to_entity ON ecs_entity_relationships(to_entity_id);
CREATE INDEX idx_ecs_entity_relationships_type ON ecs_entity_relationships(relationship_type);
CREATE INDEX idx_ecs_entity_relationships_data_gin ON ecs_entity_relationships USING gin(relationship_data);
CREATE INDEX idx_ecs_entity_relationships_created_at ON ecs_entity_relationships(created_at);
CREATE INDEX idx_ecs_entity_relationships_updated_at ON ecs_entity_relationships(updated_at);

-- Create compound index for bidirectional queries (finding relationships involving an entity)
CREATE INDEX idx_ecs_entity_relationships_bidirectional 
ON ecs_entity_relationships(from_entity_id, to_entity_id);

-- Create function to auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_ecs_entity_relationships_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to auto-update updated_at on updates
CREATE TRIGGER trigger_ecs_entity_relationships_updated_at
    BEFORE UPDATE ON ecs_entity_relationships
    FOR EACH ROW
    EXECUTE FUNCTION update_ecs_entity_relationships_updated_at();