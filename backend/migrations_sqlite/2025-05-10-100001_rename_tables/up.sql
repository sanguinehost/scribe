-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.500005
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Rename frontend tables to match backend tables
-- NOTE: This migration is frontend-specific and not applicable to backend SQLite schema
-- The backend schema never had tables named 'chats' or 'messages'
-- They were always called 'chat_sessions' and 'chat_messages'
-- Making this a no-op for backend SQLite migrations

-- ALTER TABLE chats RENAME TO old_chats;  -- Table doesn't exist in backend schema
-- ALTER TABLE messages RENAME TO old_messages;  -- Table doesn't exist in backend schema
-- ALTER TABLE votes RENAME TO old_votes;  -- Table doesn't exist in backend schema
-- ALTER TABLE documents RENAME TO old_documents;  -- Table doesn't exist in backend schema
-- ALTER TABLE suggestions RENAME TO old_suggestions;  -- Table doesn't exist in backend schema
