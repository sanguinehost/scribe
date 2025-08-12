-- Drop the index first
DROP INDEX IF EXISTS idx_agent_context_analysis_assistant_message_id;

-- Remove the assistant_message_id column
ALTER TABLE agent_context_analysis 
DROP COLUMN assistant_message_id;
