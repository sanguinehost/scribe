-- Rollback ECS entity relationships table migration
-- Drop in reverse order to avoid dependency issues

-- Drop trigger
DROP TRIGGER IF EXISTS trigger_ecs_entity_relationships_updated_at ON ecs_entity_relationships;

-- Drop function
DROP FUNCTION IF EXISTS update_ecs_entity_relationships_updated_at();

-- Drop indexes
DROP INDEX IF EXISTS idx_ecs_entity_relationships_updated_at;
DROP INDEX IF EXISTS idx_ecs_entity_relationships_created_at;
DROP INDEX IF EXISTS idx_ecs_entity_relationships_data_gin;
DROP INDEX IF EXISTS idx_ecs_entity_relationships_type;
DROP INDEX IF EXISTS idx_ecs_entity_relationships_to_entity;
DROP INDEX IF EXISTS idx_ecs_entity_relationships_from_entity;
DROP INDEX IF EXISTS idx_ecs_entity_relationships_bidirectional;
DROP INDEX IF EXISTS idx_ecs_entity_relationships_unique;

-- Drop table
DROP TABLE IF EXISTS ecs_entity_relationships;