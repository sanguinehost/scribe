-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.503919
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add agent_mode to chat_sessions for controlling context enrichment
ALTER TABLE chat_sessions
ADD COLUMN agent_mode TEXT DEFAULT 'disabled' CHECK (agent_mode IN ('disabled', 'pre_processing', 'post_processing'));

-- Create index for quick lookups
CREATE INDEX idx_chat_sessions_agent_mode ON chat_sessions(agent_mode) WHERE agent_mode != 'disabled';
