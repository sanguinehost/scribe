-- Rollback ECS components table migration
-- Drop in reverse order to avoid dependency issues

-- Drop trigger
DROP TRIGGER IF EXISTS trigger_ecs_components_updated_at ON ecs_components;

-- Drop function
DROP FUNCTION IF EXISTS update_ecs_components_updated_at();

-- Drop indexes
DROP INDEX IF EXISTS idx_ecs_components_updated_at;
DROP INDEX IF EXISTS idx_ecs_components_created_at;
DROP INDEX IF EXISTS idx_ecs_components_component_data_gin;
DROP INDEX IF EXISTS idx_ecs_components_component_type;
DROP INDEX IF EXISTS idx_ecs_components_entity_id;
DROP INDEX IF EXISTS idx_ecs_components_entity_component_unique;

-- Drop table
DROP TABLE IF EXISTS ecs_components;