-- Create usage_tracking table for billing integration and period-based usage analytics
CREATE TABLE usage_tracking (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    prompt_tokens_used BIGINT NOT NULL DEFAULT 0,
    completion_tokens_used BIGINT NOT NULL DEFAULT 0,
    estimated_cost_cents BIGINT NOT NULL DEFAULT 0,
    model_breakdown JSONB, -- {"gemini-2.5-flash": {"prompt": X, "completion": Y, "cost_cents": Z}}
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_user_period UNIQUE(user_id, period_start, period_end)
);

-- Apply updated_at trigger
SELECT diesel_manage_updated_at('usage_tracking');

-- Indexes for efficient billing queries
CREATE INDEX idx_usage_tracking_user_id ON usage_tracking (user_id);
CREATE INDEX idx_usage_tracking_period ON usage_tracking (period_start, period_end);
CREATE INDEX idx_usage_tracking_user_period ON usage_tracking (user_id, period_start, period_end);