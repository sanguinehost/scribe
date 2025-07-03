-- Add user_id columns to ECS tables for proper user isolation
-- This addresses OWASP A01: Broken Access Control

-- Add user_id to ecs_entities table
ALTER TABLE ecs_entities ADD COLUMN user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE;

-- Add user_id to ecs_components table  
ALTER TABLE ecs_components ADD COLUMN user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE;

-- Add user_id to ecs_entity_relationships table
ALTER TABLE ecs_entity_relationships ADD COLUMN user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE;

-- Add user_id to ecs_backfill_checkpoints (already exists, but ensure FK constraint)
-- ALTER TABLE ecs_backfill_checkpoints ADD CONSTRAINT fk_ecs_backfill_checkpoints_user_id 
--   FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- Create indexes for user-scoped queries
CREATE INDEX idx_ecs_entities_user_id ON ecs_entities(user_id);
CREATE INDEX idx_ecs_components_user_id ON ecs_components(user_id);
CREATE INDEX idx_ecs_entity_relationships_user_id ON ecs_entity_relationships(user_id);

-- Create composite indexes for efficient user-scoped entity queries
CREATE INDEX idx_ecs_components_user_entity ON ecs_components(user_id, entity_id);
CREATE INDEX idx_ecs_entity_relationships_user_from_to ON ecs_entity_relationships(user_id, from_entity_id, to_entity_id);
