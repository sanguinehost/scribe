-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.505465
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Fix agent_context_analysis foreign key constraint to use CASCADE on message deletion
-- This allows AI messages to be deleted even when they have associated analyses

-- SQLite Note: SQLite doesn't support modifying foreign key constraints after table creation
-- The assistant_message_id foreign key was created without ON DELETE CASCADE in the add_assistant_message_id migration
-- To change this would require table recreation. For now, CASCADE behavior must be handled at application level
-- or via a future table recreation migration if needed.

-- Drop the existing foreign key constraint that lacks CASCADE
-- -- -- -- ALTER TABLE agent_context_analysis DROP CONSTRAINT IF EXISTS agent_context_analysis_assistant_message_id_fkey; -- SQLite Note: SQLite doesn't support DROP CONSTRAINT -- SQLite Note: SQLite doesn't support DROP CONSTRAINT -- SQLite Note: SQLite doesn't support DROP CONSTRAINT

-- Re-add the foreign key constraint with CASCADE deletion
-- This ensures that when a chat_message is deleted, its associated agent_context_analysis records are also deleted
-- ALTER TABLE agent_context_analysis
-- ADD CONSTRAINT agent_context_analysis_assistant_message_id_fkey
-- FOREIGN KEY (assistant_message_id) REFERENCES chat_messages(id) ON DELETE CASCADE;
