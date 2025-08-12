-- Add message_id column to agent_context_analysis table
ALTER TABLE agent_context_analysis
ADD COLUMN message_id UUID NULL REFERENCES chat_messages(id) ON DELETE CASCADE;

-- Create index for efficient queries by session and message
CREATE INDEX idx_agent_context_analysis_session_message 
ON agent_context_analysis(chat_session_id, message_id);

-- Create index for queries by message alone
CREATE INDEX idx_agent_context_analysis_message 
ON agent_context_analysis(message_id);