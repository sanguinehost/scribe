-- Add webhook_events table for idempotency and replay protection
-- This table tracks all processed webhook events to prevent duplicate processing

CREATE TABLE webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id VARCHAR(255) NOT NULL UNIQUE,
    event_type VARCHAR(100) NOT NULL,
    paddle_signature VARCHAR(500) NOT NULL,
    payload_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of webhook payload
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processing_status VARCHAR(50) NOT NULL DEFAULT 'processed',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast lookup by event_id (primary idempotency check)
CREATE INDEX idx_webhook_events_event_id ON webhook_events(event_id);

-- Index for cleanup job (delete old events)
CREATE INDEX idx_webhook_events_created_at ON webhook_events(created_at DESC);

-- Table and column documentation
COMMENT ON TABLE webhook_events IS 'Tracks processed webhook events for idempotency and replay protection';
COMMENT ON COLUMN webhook_events.event_id IS 'Paddle event_id from webhook payload - globally unique across all event types';
COMMENT ON COLUMN webhook_events.event_type IS 'Type of webhook event (transaction.completed, subscription.created, etc.)';
COMMENT ON COLUMN webhook_events.paddle_signature IS 'Paddle-Signature header value for audit trail';
COMMENT ON COLUMN webhook_events.payload_hash IS 'SHA-256 hash of webhook payload for tamper detection';
COMMENT ON COLUMN webhook_events.processing_status IS 'Status of webhook processing (processed, failed, etc.)';
COMMENT ON COLUMN webhook_events.processed_at IS 'Timestamp when webhook was successfully processed';
COMMENT ON COLUMN webhook_events.created_at IS 'Timestamp when event record was created (for cleanup)';
