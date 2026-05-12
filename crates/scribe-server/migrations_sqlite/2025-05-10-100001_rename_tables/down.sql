-- SQLite Migration: Revert table renames
-- NOTE: chats/messages tables don't exist in backend schema

-- Revert the renames (skip chats/messages that don't exist)
ALTER TABLE IF EXISTS old_votes RENAME TO votes;
ALTER TABLE IF EXISTS old_documents RENAME TO documents;
ALTER TABLE IF EXISTS old_suggestions RENAME TO suggestions;
