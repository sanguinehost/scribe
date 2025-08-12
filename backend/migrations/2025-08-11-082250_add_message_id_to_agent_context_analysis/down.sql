-- Drop indexes
DROP INDEX IF EXISTS idx_agent_context_analysis_message;
DROP INDEX IF EXISTS idx_agent_context_analysis_session_message;

-- Remove message_id column
ALTER TABLE agent_context_analysis
DROP COLUMN message_id;