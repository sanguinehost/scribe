-- Payment audit logs table - privacy-focused design
-- Only tracks what's absolutely necessary for financial compliance and debugging
CREATE TABLE payment_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- User reference (hashed for privacy)
    user_id_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of user_id for correlation without direct identification
    
    -- Essential event tracking
    event_type VARCHAR(50) NOT NULL, -- credit_added, credit_deducted, subscription_created, etc.
    amount INTEGER, -- Amount in credits or cents (nullable for non-monetary events)
    
    -- Minimal description (no PII)
    event_category VARCHAR(30) NOT NULL, -- 'credit', 'subscription', 'payment', 'webhook'
    
    -- Success/failure tracking for debugging
    success BOOLEAN NOT NULL DEFAULT true,
    error_code VARCHAR(50), -- Generic error code, no sensitive details
    
    -- External reference for payment processor reconciliation only
    external_reference_hash VARCHAR(64), -- Hashed Paddle/Stripe transaction ID
    
    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Minimal indexes for performance
CREATE INDEX idx_payment_audit_created_at ON payment_audit_logs(created_at);
CREATE INDEX idx_payment_audit_event_type ON payment_audit_logs(event_type);
CREATE INDEX idx_payment_audit_user_hash ON payment_audit_logs(user_id_hash);

-- Automatic cleanup after 30 days (configurable)
COMMENT ON TABLE payment_audit_logs IS 'Privacy-focused audit logs. Auto-purged after 30 days. No PII stored.';
