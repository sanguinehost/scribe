-- Fix chronicle_events foreign key constraint to use CASCADE on chat session deletion
-- This allows chat sessions to be deleted even when they have chronicle events

-- Drop the existing foreign key constraint that lacks CASCADE
ALTER TABLE chronicle_events 
DROP CONSTRAINT IF EXISTS chronicle_events_chat_session_id_fkey;

-- Re-add the foreign key constraint with CASCADE deletion
-- This ensures that when a chat_session is deleted, its associated chronicle_events are also deleted
ALTER TABLE chronicle_events 
ADD CONSTRAINT chronicle_events_chat_session_id_fkey 
FOREIGN KEY (chat_session_id) REFERENCES chat_sessions(id) ON DELETE CASCADE;
