-- Create agent_context_analysis table for storing agent's context enrichment work
CREATE TABLE agent_context_analysis (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_session_id UUID NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    analysis_type VARCHAR(50) NOT NULL CHECK (analysis_type IN ('pre_processing', 'post_processing')),
    
    -- Agent thought process (encrypted)
    agent_reasoning TEXT,
    agent_reasoning_nonce BYTEA,
    
    -- Planning phase - stores JSON array of planned searches
    planned_searches JSONB,
    
    -- Execution audit trail (encrypted) - full log of all tool calls and responses
    execution_log JSONB,
    execution_log_nonce BYTEA,
    
    -- Final results (encrypted)
    retrieved_context TEXT,
    retrieved_context_nonce BYTEA,
    analysis_summary TEXT,
    analysis_summary_nonce BYTEA,
    
    -- Performance metrics
    total_tokens_used INTEGER,
    execution_time_ms INTEGER,
    model_used VARCHAR(100),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Ensure only one analysis per session per type
    UNIQUE(chat_session_id, analysis_type)
);

-- Index for quick retrieval by session
CREATE INDEX idx_agent_context_session ON agent_context_analysis(chat_session_id);

-- Index for user's analyses
CREATE INDEX idx_agent_context_user ON agent_context_analysis(user_id);

-- Add trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_agent_context_analysis_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_agent_context_analysis_updated_at
    BEFORE UPDATE ON agent_context_analysis
    FOR EACH ROW
    EXECUTE FUNCTION update_agent_context_analysis_updated_at();
