-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.504297
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- First, delete any orphaned analyses without message_id (these are invalid data)
DELETE FROM agent_context_analysis WHERE message_id IS NULL;

-- Now make message_id NOT NULL
-- SQLite Note: Making message_id NOT NULL requires table recreation - defer to fix_nullable_columns.py
-- ALTER TABLE agent_context_analysis ALTER COLUMN message_id SET NOT NULL;
