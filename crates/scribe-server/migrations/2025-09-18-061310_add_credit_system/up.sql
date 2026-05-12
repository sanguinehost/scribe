-- Credit System Tables
-- Only added when payment feature is enabled
-- These tables support the hybrid subscription + credit model

-- User credit balances
CREATE TABLE IF NOT EXISTS user_credits (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    balance INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
    lifetime_earned INTEGER NOT NULL DEFAULT 0,
    lifetime_spent INTEGER NOT NULL DEFAULT 0,
    last_monthly_grant TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Credit transaction history for audit trail
CREATE TABLE IF NOT EXISTS credit_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    amount INTEGER NOT NULL, -- positive for credits, negative for debits
    balance_after INTEGER NOT NULL,
    transaction_type VARCHAR(50) NOT NULL, -- 'purchase', 'monthly_grant', 'usage', 'refund', 'adjustment', 'bonus'
    -- Description is encrypted with user's DEK as it may contain sensitive info
    description_encrypted BYTEA NOT NULL,
    description_nonce BYTEA NOT NULL,
    -- Encrypted metadata for sensitive transaction details (JSON with user context)
    metadata_encrypted BYTEA,
    metadata_nonce BYTEA,
    -- Reference to external system (e.g., Paddle transaction ID) - not encrypted as it's a reference
    reference_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Daily usage tracking for soft limits
CREATE TABLE IF NOT EXISTS daily_usage_tracking (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    date DATE NOT NULL,
    message_count INTEGER NOT NULL DEFAULT 0,
    token_count BIGINT NOT NULL DEFAULT 0,
    -- Model usage breakdown (JSON: {"gemini-2.5-flash": 45, "gemini-2.5-pro": 5})
    model_breakdown JSONB,
    -- Message number when soft limit was triggered (NULL if not triggered)
    soft_limit_triggered_at INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    -- Ensure only one entry per user per day
    UNIQUE(user_id, date)
);

-- Credit packages available for purchase
CREATE TABLE IF NOT EXISTS credit_packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_id VARCHAR(50) UNIQUE NOT NULL, -- e.g., 'credits_250', 'credits_1500'
    name VARCHAR(100) NOT NULL,
    credits INTEGER NOT NULL,
    price_cents INTEGER NOT NULL,
    bonus_percentage INTEGER DEFAULT 0,
    paddle_price_id VARCHAR(255),
    active BOOLEAN DEFAULT true,
    display_order INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Extend existing subscriptions table
ALTER TABLE subscriptions
ADD COLUMN IF NOT EXISTS credits_allocated_this_period BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS soft_limit_override INTEGER, -- Admin can set custom daily limit
ADD COLUMN IF NOT EXISTS last_credit_grant TIMESTAMP WITH TIME ZONE;

-- Extend existing users table for quick lookups
ALTER TABLE users
ADD COLUMN IF NOT EXISTS cached_credit_balance INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cached_subscription_tier VARCHAR(50),
ADD COLUMN IF NOT EXISTS last_daily_usage_reset TIMESTAMP WITH TIME ZONE;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_credit_transactions_user_id
    ON credit_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_created_at
    ON credit_transactions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_type
    ON credit_transactions(transaction_type);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_reference
    ON credit_transactions(reference_id)
    WHERE reference_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_daily_usage_user_date
    ON daily_usage_tracking(user_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_daily_usage_date
    ON daily_usage_tracking(date DESC);
CREATE INDEX IF NOT EXISTS idx_daily_usage_soft_limit
    ON daily_usage_tracking(soft_limit_triggered_at)
    WHERE soft_limit_triggered_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_credit_packages_active
    ON credit_packages(active, display_order)
    WHERE active = true;

-- Insert default credit packages (matching subscription_tiers.json)
INSERT INTO credit_packages (package_id, name, credits, price_cents, bonus_percentage, paddle_price_id, display_order) VALUES
    ('credits_250', 'Starter Pack', 250, 500, 0, 'pri_credits_250', 1),
    ('credits_550', 'Value Pack', 550, 1000, 10, 'pri_credits_550', 2),
    ('credits_1500', 'Power Pack', 1500, 2500, 20, 'pri_credits_1500', 3),
    ('credits_3500', 'Ultra Pack', 3500, 5000, 40, 'pri_credits_3500', 4),
    ('credits_8000', 'Mega Pack', 8000, 10000, 60, 'pri_credits_8000', 5)
ON CONFLICT (package_id) DO NOTHING;

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for updated_at
CREATE TRIGGER update_user_credits_updated_at
    BEFORE UPDATE ON user_credits
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_daily_usage_tracking_updated_at
    BEFORE UPDATE ON daily_usage_tracking
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_credit_packages_updated_at
    BEFORE UPDATE ON credit_packages
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
