-- Remove encryption support from ECS components

DROP INDEX IF EXISTS idx_ecs_components_type_user;
ALTER TABLE ecs_components DROP COLUMN IF EXISTS component_data_nonce;
ALTER TABLE ecs_components DROP COLUMN IF EXISTS encrypted_component_data;
