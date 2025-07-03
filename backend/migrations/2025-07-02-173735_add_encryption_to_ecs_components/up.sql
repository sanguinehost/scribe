-- Add encryption support to ECS components for sensitive data
-- This addresses OWASP A02: Cryptographic Failures

-- Replace component_data JSONB with encrypted_component_data BYTEA
ALTER TABLE ecs_components ADD COLUMN encrypted_component_data BYTEA;
ALTER TABLE ecs_components ADD COLUMN component_data_nonce BYTEA;

-- Keep component_data for backward compatibility during migration
-- Will be removed in a future migration once all data is migrated

-- Create index for encrypted component queries
CREATE INDEX idx_ecs_components_type_user ON ecs_components(component_type, user_id);
