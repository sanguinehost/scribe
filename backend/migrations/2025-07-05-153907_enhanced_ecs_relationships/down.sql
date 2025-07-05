-- Rollback: Remove Enhanced ECS Relationships
-- This rollback removes the temporal knowledge graph enhancements

-- Remove indexes first
DROP INDEX IF EXISTS idx_chronicle_causes_events;
DROP INDEX IF EXISTS idx_chronicle_causal_chain;
DROP INDEX IF EXISTS idx_ecs_relationships_temporal;
DROP INDEX IF EXISTS idx_ecs_relationships_strength;
DROP INDEX IF EXISTS idx_ecs_relationships_category;

-- Remove causal tracking from chronicle events
ALTER TABLE chronicle_events
DROP COLUMN IF EXISTS causes_event_ids,
DROP COLUMN IF EXISTS caused_by_event_id;

-- Remove graph-like metadata from relationships
ALTER TABLE ecs_entity_relationships 
DROP COLUMN IF EXISTS temporal_validity,
DROP COLUMN IF EXISTS causal_metadata,
DROP COLUMN IF EXISTS strength,
DROP COLUMN IF EXISTS relationship_category;
