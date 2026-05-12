-- Drop the new unique constraint
ALTER TABLE agent_context_analysis
DROP CONSTRAINT IF EXISTS agent_context_analysis_chat_session_message_type_key;

-- Restore the old unique constraint (session + analysis_type only)
ALTER TABLE agent_context_analysis
ADD CONSTRAINT agent_context_analysis_chat_session_id_analysis_type_key
UNIQUE (chat_session_id, analysis_type);
