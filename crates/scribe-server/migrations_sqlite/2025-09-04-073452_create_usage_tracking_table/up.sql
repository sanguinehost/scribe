-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.506495
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Create usage_tracking table for billing integration and period-based usage analytics
CREATE TABLE usage_tracking (
    id TEXT PRIMARY KEY ,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    period_start DATETIME NOT NULL,
    period_end DATETIME NOT NULL,
    prompt_tokens_used INTEGER NOT NULL DEFAULT 0,
    completion_tokens_used INTEGER NOT NULL DEFAULT 0,
    estimated_cost_cents INTEGER NOT NULL DEFAULT 0,
    model_breakdown TEXT, -- {"gemini-2.5-flash": {"prompt": X, "completion": Y, "cost_cents": Z}}
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_user_period UNIQUE(user_id, period_start, period_end)
);

-- Apply updated_at trigger

-- SQLite trigger for updating timestamps on usage_tracking
CREATE TRIGGER IF NOT EXISTS update_usage_tracking_timestamp
AFTER UPDATE ON usage_tracking
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE usage_tracking SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Indexes for efficient billing queries
CREATE INDEX idx_usage_tracking_user_id ON usage_tracking (user_id);
CREATE INDEX idx_usage_tracking_period ON usage_tracking (period_start, period_end);
CREATE INDEX idx_usage_tracking_user_period ON usage_tracking (user_id, period_start, period_end);
