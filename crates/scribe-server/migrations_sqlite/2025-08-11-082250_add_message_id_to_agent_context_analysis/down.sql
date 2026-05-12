-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.504219
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop indexes
DROP INDEX IF EXISTS idx_agent_context_analysis_message;
DROP INDEX IF EXISTS idx_agent_context_analysis_session_message;

-- Remove message_id column
ALTER TABLE agent_context_analysis
DROP COLUMN message_id;
