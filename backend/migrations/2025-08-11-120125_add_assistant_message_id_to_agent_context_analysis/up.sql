-- Add assistant_message_id column to agent_context_analysis table
-- This allows us to associate analyses with both user and assistant messages
ALTER TABLE agent_context_analysis 
ADD COLUMN assistant_message_id UUID REFERENCES chat_messages(id);

-- Create index for efficient querying by assistant message
CREATE INDEX idx_agent_context_analysis_assistant_message_id 
ON agent_context_analysis(assistant_message_id);

-- Add comment explaining the dual association
COMMENT ON COLUMN agent_context_analysis.assistant_message_id IS 
'ID of the assistant message this analysis is associated with. For pre-processing, this is set after the assistant message is created. For post-processing, this is the message that triggered the analysis.';
