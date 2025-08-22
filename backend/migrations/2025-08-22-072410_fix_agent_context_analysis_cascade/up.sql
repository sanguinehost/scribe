-- Fix agent_context_analysis foreign key constraint to use CASCADE on message deletion
-- This allows AI messages to be deleted even when they have associated analyses

-- Drop the existing foreign key constraint that lacks CASCADE
ALTER TABLE agent_context_analysis 
DROP CONSTRAINT IF EXISTS agent_context_analysis_assistant_message_id_fkey;

-- Re-add the foreign key constraint with CASCADE deletion
-- This ensures that when a chat_message is deleted, its associated agent_context_analysis records are also deleted
ALTER TABLE agent_context_analysis 
ADD CONSTRAINT agent_context_analysis_assistant_message_id_fkey 
FOREIGN KEY (assistant_message_id) REFERENCES chat_messages(id) ON DELETE CASCADE;
