-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.507977
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop the old unique constraint that prevents multiple analyses per session
ALTER TABLE agent_context_analysis
DROP CONSTRAINT IF EXISTS agent_context_analysis_chat_session_id_analysis_type_key;

-- Add new unique constraint that allows one analysis per message
-- This allows multiple pre_processing analyses per session (one for each user message)
ALTER TABLE agent_context_analysis
ADD CONSTRAINT agent_context_analysis_chat_session_message_type_key
UNIQUE (chat_session_id, analysis_type, message_id);
