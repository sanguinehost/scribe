-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.507977
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop the old unique constraint that prevents multiple analyses per session
-- -- -- ALTER TABLE agent_context_analysis
-- DROP CONSTRAINT IF EXISTS agent_context_analysis_chat_session_id_analysis_type_key; -- SQLite Note: SQLite doesn't support DROP CONSTRAINT

-- Add new unique constraint that allows one analysis per message
-- This allows multiple pre_processing analyses per session (one for each user message)
-- SQLite Note: Unique constraints can't be dropped/added directly in SQLite
-- Create a unique index instead to enforce the constraint
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_context_analysis_unique_per_message
ON agent_context_analysis (chat_session_id, analysis_type, message_id)
WHERE message_id IS NOT NULL;
