-- Create ECS components table
-- Task 1.1.2: Create hybrid ecs_components table with JSONB for flexible component data

-- Create ecs_components table with hybrid relational-document schema
CREATE TABLE ecs_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id UUID NOT NULL,
    component_type TEXT NOT NULL,
    component_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (entity_id) REFERENCES ecs_entities(id) ON DELETE CASCADE
);

-- Create unique constraint to prevent duplicate component types per entity
CREATE UNIQUE INDEX idx_ecs_components_entity_component_unique 
ON ecs_components(entity_id, component_type);

-- Create indexes for performance
CREATE INDEX idx_ecs_components_entity_id ON ecs_components(entity_id);
CREATE INDEX idx_ecs_components_component_type ON ecs_components(component_type);
CREATE INDEX idx_ecs_components_component_data_gin ON ecs_components USING gin(component_data);
CREATE INDEX idx_ecs_components_created_at ON ecs_components(created_at);
CREATE INDEX idx_ecs_components_updated_at ON ecs_components(updated_at);

-- Create function to auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_ecs_components_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to auto-update updated_at on updates
CREATE TRIGGER trigger_ecs_components_updated_at
    BEFORE UPDATE ON ecs_components
    FOR EACH ROW
    EXECUTE FUNCTION update_ecs_components_updated_at();