-- Create agent_results table for storing encrypted agent processing results
-- This table enables progressive enrichment by storing perception, tactical, and strategic agent outputs

CREATE TABLE agent_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message_id UUID NULL, -- Can be null for background tasks not tied to specific messages
    agent_type VARCHAR(50) NOT NULL, -- 'perception', 'tactical', 'strategic', 'orchestrator'
    operation_type VARCHAR(100) NOT NULL, -- e.g., 'perception_analysis', 'tactical_planning', 'entity_extraction'
    
    -- Encrypted result payload (JSON structure)
    encrypted_result BYTEA NOT NULL,
    result_nonce BYTEA NOT NULL,
    
    -- Encrypted metadata (includes processing stats, confidence scores, etc.)
    encrypted_metadata BYTEA NULL,
    metadata_nonce BYTEA NULL,
    
    -- Processing information
    processing_time_ms INTEGER NOT NULL,
    token_count INTEGER NULL,
    confidence_score REAL NULL CHECK (confidence_score >= 0 AND confidence_score <= 1),
    
    -- Status tracking
    status VARCHAR(20) NOT NULL DEFAULT 'completed', -- 'pending', 'processing', 'completed', 'failed'
    error_message TEXT NULL,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retrieved_at TIMESTAMPTZ NULL, -- Track when lightning agent retrieves this result
    
    -- Phase tracking for atomic coordination (Phase 3/4 support)
    processing_phase VARCHAR(10) NULL, -- '3.0', '4.0', etc.
    coordination_key VARCHAR(255) NULL -- For SharedAgentContext compatibility
);

-- Indexes for efficient retrieval by lightning agent
CREATE INDEX idx_agent_results_session_user 
ON agent_results(session_id, user_id);

-- Index for retrieving unretrieved results for a session
CREATE INDEX idx_agent_results_unretrieved 
ON agent_results(session_id, retrieved_at) 
WHERE retrieved_at IS NULL;

-- Index for agent type filtering
CREATE INDEX idx_agent_results_agent_type 
ON agent_results(agent_type, session_id);

-- Index for operation type queries
CREATE INDEX idx_agent_results_operation 
ON agent_results(operation_type, session_id);

-- Index for coordination queries (Phase 3/4)
CREATE INDEX idx_agent_results_coordination 
ON agent_results(coordination_key) 
WHERE coordination_key IS NOT NULL;

-- Composite index for temporal queries
CREATE INDEX idx_agent_results_temporal 
ON agent_results(session_id, created_at DESC);

-- Function to update retrieved_at when results are accessed
CREATE OR REPLACE FUNCTION mark_agent_results_retrieved(
    p_session_id UUID,
    p_user_id UUID,
    p_cutoff_time TIMESTAMPTZ DEFAULT NOW()
) RETURNS INTEGER AS $$
DECLARE
    rows_updated INTEGER;
BEGIN
    UPDATE agent_results 
    SET retrieved_at = NOW()
    WHERE session_id = p_session_id 
      AND user_id = p_user_id
      AND retrieved_at IS NULL
      AND created_at <= p_cutoff_time;
    
    GET DIAGNOSTICS rows_updated = ROW_COUNT;
    RETURN rows_updated;
END;
$$ LANGUAGE plpgsql;

-- Create a view for easy querying of unretrieved results
CREATE VIEW unretrieved_agent_results AS
SELECT 
    ar.id,
    ar.session_id,
    ar.user_id,
    ar.agent_type,
    ar.operation_type,
    ar.processing_time_ms,
    ar.confidence_score,
    ar.created_at,
    COUNT(*) OVER (PARTITION BY ar.session_id) as total_unretrieved
FROM agent_results ar
WHERE ar.retrieved_at IS NULL
  AND ar.status = 'completed'
ORDER BY ar.created_at DESC;