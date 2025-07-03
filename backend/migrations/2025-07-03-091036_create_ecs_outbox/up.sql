-- Create ECS Outbox table for transactional outbox pattern
-- This ensures reliable event delivery from ECS state changes

CREATE TABLE ecs_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    sequence_number BIGSERIAL NOT NULL,
    event_type VARCHAR(255) NOT NULL,
    entity_id UUID,
    component_type VARCHAR(255),
    event_data JSONB NOT NULL,
    aggregate_id UUID,
    aggregate_type VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMPTZ,
    delivery_status VARCHAR(50) NOT NULL DEFAULT 'pending',
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    next_retry_at TIMESTAMPTZ,
    error_message TEXT,
    
    -- Ensure ordering within user scope
    CONSTRAINT fk_ecs_outbox_user_id 
        FOREIGN KEY (user_id) 
        REFERENCES users(id) 
        ON DELETE CASCADE,
        
    -- Optional reference to entity if event is entity-specific
    CONSTRAINT fk_ecs_outbox_entity_id 
        FOREIGN KEY (entity_id) 
        REFERENCES ecs_entities(id) 
        ON DELETE SET NULL,
        
    -- Validate delivery status
    CONSTRAINT chk_delivery_status 
        CHECK (delivery_status IN ('pending', 'processing', 'delivered', 'failed', 'dead_letter'))
);

-- Indexes for efficient processing
CREATE INDEX idx_ecs_outbox_user_sequence ON ecs_outbox(user_id, sequence_number);
CREATE INDEX idx_ecs_outbox_delivery_status ON ecs_outbox(delivery_status);
CREATE INDEX idx_ecs_outbox_created_at ON ecs_outbox(created_at);
CREATE INDEX idx_ecs_outbox_next_retry ON ecs_outbox(next_retry_at) WHERE delivery_status = 'failed';
CREATE INDEX idx_ecs_outbox_event_type ON ecs_outbox(event_type);
CREATE INDEX idx_ecs_outbox_entity_component ON ecs_outbox(entity_id, component_type) WHERE entity_id IS NOT NULL;

-- Index for processing order (undelivered events by sequence)
CREATE INDEX idx_ecs_outbox_processing_order ON ecs_outbox(user_id, sequence_number) 
    WHERE delivery_status IN ('pending', 'failed');