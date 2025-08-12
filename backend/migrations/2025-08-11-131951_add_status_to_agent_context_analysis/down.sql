-- Drop the index first
DROP INDEX IF EXISTS idx_agent_context_analysis_active;

-- Remove the added columns
ALTER TABLE agent_context_analysis 
DROP COLUMN status;

ALTER TABLE agent_context_analysis 
DROP COLUMN error_message;

ALTER TABLE agent_context_analysis 
DROP COLUMN retry_count;

ALTER TABLE agent_context_analysis 
DROP COLUMN superseded_at;