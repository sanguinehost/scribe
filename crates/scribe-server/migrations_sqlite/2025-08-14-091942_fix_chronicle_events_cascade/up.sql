-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.505172
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Fix chronicle_events foreign key constraint to use CASCADE on chat session deletion
-- This allows chat sessions to be deleted even when they have chronicle events

-- SQLite Note: SQLite doesn't support modifying foreign key constraints after table creation
-- The chat_session_id foreign key was created without ON DELETE CASCADE in the simplify_chronicle_events migration
-- To change this would require table recreation. For now, CASCADE behavior must be handled at application level
-- or via a future table recreation migration if needed.

-- Drop the existing foreign key constraint that lacks CASCADE
-- -- -- -- ALTER TABLE chronicle_events DROP CONSTRAINT IF EXISTS chronicle_events_chat_session_id_fkey; -- SQLite Note: SQLite doesn't support DROP CONSTRAINT -- SQLite Note: SQLite doesn't support DROP CONSTRAINT -- SQLite Note: SQLite doesn't support DROP CONSTRAINT

-- Re-add the foreign key constraint with CASCADE deletion
-- This ensures that when a chat_session is deleted, its associated chronicle_events are also deleted
-- ALTER TABLE chronicle_events
-- ADD CONSTRAINT chronicle_events_chat_session_id_fkey
-- FOREIGN KEY (chat_session_id) REFERENCES chat_sessions(id) ON DELETE CASCADE;
