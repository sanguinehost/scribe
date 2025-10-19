-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.500005
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Rename frontend tables to match backend tables
ALTER TABLE IF EXISTS chats RENAME TO old_chats;
ALTER TABLE IF EXISTS messages RENAME TO old_messages;
ALTER TABLE IF EXISTS votes RENAME TO old_votes;
ALTER TABLE IF EXISTS documents RENAME TO old_documents;
ALTER TABLE IF EXISTS suggestions RENAME TO old_suggestions;
