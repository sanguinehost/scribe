-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.504879
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

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
