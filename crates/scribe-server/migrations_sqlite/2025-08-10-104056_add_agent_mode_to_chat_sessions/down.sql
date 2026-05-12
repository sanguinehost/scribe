-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.504026
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop the index
DROP INDEX IF EXISTS idx_chat_sessions_agent_mode;

-- Remove the agent_mode column
ALTER TABLE chat_sessions DROP COLUMN agent_mode;
