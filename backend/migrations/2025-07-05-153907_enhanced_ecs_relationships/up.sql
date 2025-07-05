-- Migration: Enhanced ECS Relationships for Graph-like Capabilities
-- This migration extends the existing ECS with temporal knowledge graph features
-- while maintaining backwards compatibility and performance

-- Add graph-like metadata to relationships
ALTER TABLE ecs_entity_relationships 
ADD COLUMN relationship_category VARCHAR(50) DEFAULT 'social',
ADD COLUMN strength FLOAT DEFAULT 0.5 CHECK (strength >= 0.0 AND strength <= 1.0),
ADD COLUMN causal_metadata JSONB DEFAULT '{}',
ADD COLUMN temporal_validity JSONB DEFAULT '{}';

-- Add indexes for efficient graph queries
CREATE INDEX idx_ecs_relationships_category ON ecs_entity_relationships(relationship_category);
CREATE INDEX idx_ecs_relationships_strength ON ecs_entity_relationships(strength);
CREATE INDEX idx_ecs_relationships_temporal ON ecs_entity_relationships USING GIN(temporal_validity);

-- Add causal tracking to chronicle events
ALTER TABLE chronicle_events
ADD COLUMN caused_by_event_id UUID REFERENCES chronicle_events(id),
ADD COLUMN causes_event_ids UUID[] DEFAULT '{}';

CREATE INDEX idx_chronicle_causal_chain ON chronicle_events(caused_by_event_id);
CREATE INDEX idx_chronicle_causes_events ON chronicle_events USING GIN(causes_event_ids);

-- Add comments for documentation
COMMENT ON COLUMN ecs_entity_relationships.relationship_category IS 'Category of relationship: social, spatial, causal, ownership, temporal';
COMMENT ON COLUMN ecs_entity_relationships.strength IS 'Relationship strength from 0.0 to 1.0';
COMMENT ON COLUMN ecs_entity_relationships.causal_metadata IS 'Metadata about causal relationships: {caused_by_event: UUID, confidence: float, causality_type: string}';
COMMENT ON COLUMN ecs_entity_relationships.temporal_validity IS 'Temporal validity: {valid_from: timestamp, valid_until: timestamp, confidence: float}';
COMMENT ON COLUMN chronicle_events.caused_by_event_id IS 'ID of the event that caused this event (causal chain)';
COMMENT ON COLUMN chronicle_events.causes_event_ids IS 'Array of event IDs that this event causes (forward causal links)';
