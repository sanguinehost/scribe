-- Store Paddle transaction data for verification and reconciliation
-- All sensitive customer data is encrypted with user's DEK per ENCRYPTION_ARCHITECTURE.md
CREATE TABLE payment_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    paddle_transaction_id VARCHAR(255) NOT NULL UNIQUE,
    user_id UUID REFERENCES users(id) NOT NULL,
    status VARCHAR(50) NOT NULL, -- 'created', 'ready', 'billed', 'completed', 'cancelled', 'past_due'
    collection_mode VARCHAR(50), -- 'automatic', 'manual'

    -- Non-sensitive financial amounts (needed for reconciliation)
    total_cents INTEGER NOT NULL,
    tax_cents INTEGER,
    discount_cents INTEGER,
    currency_code VARCHAR(3) DEFAULT 'USD',

    -- Paddle customer ID (not sensitive - just an ID)
    paddle_customer_id VARCHAR(255),

    -- All customer PII is encrypted with user's DEK
    -- This includes email, name, billing address, etc.
    customer_data_encrypted BYTEA, -- Encrypted JSON with email, name, etc.
    customer_data_nonce BYTEA,

    -- Items purchased (just IDs and quantities, no PII)
    items JSONB NOT NULL,

    -- Checkout ID (non-sensitive reference)
    checkout_id VARCHAR(255),

    -- Timestamps from Paddle (non-sensitive)
    billed_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Full transaction data from Paddle (encrypted - may contain PII)
    paddle_data_encrypted BYTEA,
    paddle_data_nonce BYTEA,

    -- Local timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance (only on non-encrypted fields)
CREATE INDEX idx_payment_transactions_paddle_id ON payment_transactions(paddle_transaction_id);
CREATE INDEX idx_payment_transactions_user_id ON payment_transactions(user_id);
CREATE INDEX idx_payment_transactions_paddle_customer_id ON payment_transactions(paddle_customer_id);
CREATE INDEX idx_payment_transactions_status ON payment_transactions(status);
CREATE INDEX idx_payment_transactions_created_at ON payment_transactions(created_at);
CREATE INDEX idx_payment_transactions_checkout_id ON payment_transactions(checkout_id);