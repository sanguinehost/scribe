-- Rollback ECS entities table migration
-- Drop in reverse order to avoid dependency issues

-- Drop trigger
DROP TRIGGER IF EXISTS trigger_ecs_entities_updated_at ON ecs_entities;

-- Drop function
DROP FUNCTION IF EXISTS update_ecs_entities_updated_at();

-- Drop indexes
DROP INDEX IF EXISTS idx_ecs_entities_updated_at;
DROP INDEX IF EXISTS idx_ecs_entities_created_at;
DROP INDEX IF EXISTS idx_ecs_entities_archetype_signature;

-- Drop table
DROP TABLE IF EXISTS ecs_entities;