-- SQLite Migration: Rename frontend tables to match backend tables
-- NOTE: chats/messages tables don't exist in backend (always chat_sessions/chat_messages)
-- But votes, documents, suggestions DO exist and need renaming

-- Skip chats and messages (don't exist in backend schema)
-- ALTER TABLE chats RENAME TO old_chats;
-- ALTER TABLE messages RENAME TO old_messages;

-- Rename tables that DO exist
ALTER TABLE votes RENAME TO old_votes;
ALTER TABLE documents RENAME TO old_documents;
ALTER TABLE suggestions RENAME TO old_suggestions;
