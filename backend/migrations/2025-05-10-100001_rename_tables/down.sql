-- Revert the renames
ALTER TABLE IF EXISTS old_chats RENAME TO chats;
ALTER TABLE IF EXISTS old_messages RENAME TO messages;
ALTER TABLE IF EXISTS old_votes RENAME TO votes;
ALTER TABLE IF EXISTS old_documents RENAME TO documents;
ALTER TABLE IF EXISTS old_suggestions RENAME TO suggestions; 