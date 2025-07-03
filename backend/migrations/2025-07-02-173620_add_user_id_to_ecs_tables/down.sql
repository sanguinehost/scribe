-- Remove user_id columns from ECS tables

-- Drop indexes
DROP INDEX IF EXISTS idx_ecs_entity_relationships_user_from_to;
DROP INDEX IF EXISTS idx_ecs_components_user_entity;
DROP INDEX IF EXISTS idx_ecs_entity_relationships_user_id;
DROP INDEX IF EXISTS idx_ecs_components_user_id;
DROP INDEX IF EXISTS idx_ecs_entities_user_id;

-- Remove user_id columns
ALTER TABLE ecs_entity_relationships DROP COLUMN IF EXISTS user_id;
ALTER TABLE ecs_components DROP COLUMN IF EXISTS user_id;
ALTER TABLE ecs_entities DROP COLUMN IF EXISTS user_id;
