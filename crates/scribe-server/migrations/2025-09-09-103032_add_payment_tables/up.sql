-- Add payment-related tables with encryption for sensitive data
-- All sensitive user data will be encrypted using the user's existing DEK

-- Plan features table (public information, no encryption needed)
CREATE TABLE plan_features (
    plan_type VARCHAR(50) PRIMARY KEY,
    monthly_token_limit INTEGER,
    characters_limit INTEGER,
    lorebooks_limit INTEGER,
    price_cents INTEGER,
    paddle_price_id VARCHAR(255),
    features JSONB,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Subscriptions table (minimal encryption - most fields are operational metadata)
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) NOT NULL,
    paddle_customer_id VARCHAR(255),
    paddle_subscription_id VARCHAR(255) UNIQUE,
    plan_type VARCHAR(50) REFERENCES plan_features(plan_type) NOT NULL,
    status VARCHAR(50) NOT NULL, -- 'active', 'cancelled', 'past_due', 'trialing'
    current_period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    current_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    trial_end TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Payments table (encrypt sensitive failure reasons and metadata)
CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) NOT NULL,
    subscription_id UUID REFERENCES subscriptions(id),
    paddle_transaction_id VARCHAR(255),
    amount_cents INTEGER NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    status VARCHAR(50) NOT NULL, -- 'pending', 'succeeded', 'failed', 'refunded'
    failure_reason_encrypted BYTEA, -- Encrypted sensitive failure details
    failure_reason_nonce BYTEA,
    paddle_receipt_url VARCHAR(512),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Payment usage tracking table (encrypt metadata that might contain usage patterns)
CREATE TABLE payment_usage_tracking (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) NOT NULL,
    subscription_id UUID REFERENCES subscriptions(id),
    tokens_used INTEGER NOT NULL,
    tokens_limit INTEGER,
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    metadata_encrypted BYTEA, -- Encrypted usage patterns/details
    metadata_nonce BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX idx_subscriptions_paddle_subscription_id ON subscriptions(paddle_subscription_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);

CREATE INDEX idx_payments_user_id ON payments(user_id);
CREATE INDEX idx_payments_subscription_id ON payments(subscription_id);
CREATE INDEX idx_payments_status ON payments(status);
CREATE INDEX idx_payments_created_at ON payments(created_at);

CREATE INDEX idx_payment_usage_tracking_user_id ON payment_usage_tracking(user_id);
CREATE INDEX idx_payment_usage_tracking_subscription_id ON payment_usage_tracking(subscription_id);
CREATE INDEX idx_payment_usage_tracking_period ON payment_usage_tracking(period_start, period_end);

-- Insert default plan features with actual Paddle price IDs
INSERT INTO plan_features (plan_type, monthly_token_limit, characters_limit, lorebooks_limit, price_cents, paddle_price_id, display_name, description, features) VALUES
('free', 50000, 5, 1, 0, NULL, 'Free', 'Perfect for trying out character AI conversations', '{"priority_support": false, "advanced_models": false, "api_access": false}'),
('pro', 500000, 50, 10, 999, 'pri_01k4qbyetvn495nzv9nkqhxz02', 'Pro', 'For serious character AI enthusiasts and creators', '{"priority_support": true, "advanced_models": true, "api_access": false, "custom_personas": true}'),
('enterprise', -1, -1, -1, 2999, NULL, 'Enterprise', 'Unlimited usage for professionals and teams (contact for setup)', '{"priority_support": true, "advanced_models": true, "api_access": true, "custom_personas": true, "white_label": true}');
