-- Add status field to track analysis state
ALTER TABLE agent_context_analysis 
ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'success';

-- Add error_message field to store failure reasons
ALTER TABLE agent_context_analysis 
ADD COLUMN error_message TEXT;

-- Add retry_count to track retry attempts
ALTER TABLE agent_context_analysis 
ADD COLUMN retry_count INT4 NOT NULL DEFAULT 0;

-- Add superseded_at to mark old failed analyses
ALTER TABLE agent_context_analysis 
ADD COLUMN superseded_at TIMESTAMPTZ;

-- Create index for finding active analyses (not superseded)
CREATE INDEX idx_agent_context_analysis_active 
ON agent_context_analysis(chat_session_id, analysis_type, status) 
WHERE superseded_at IS NULL;

-- Update existing records to have 'success' status (they wouldn't exist if they failed)
-- This is already handled by the DEFAULT value