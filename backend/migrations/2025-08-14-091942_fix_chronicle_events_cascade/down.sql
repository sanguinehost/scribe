-- Revert to the original foreign key constraint without CASCADE
-- This undoes the CASCADE deletion behavior added in the up.sql

-- Drop the CASCADE foreign key constraint
ALTER TABLE chronicle_events 
DROP CONSTRAINT IF EXISTS chronicle_events_chat_session_id_fkey;

-- Re-add the original foreign key constraint without CASCADE
-- This restores the original behavior that prevented chat_session deletion when chronicle_events exist
ALTER TABLE chronicle_events 
ADD CONSTRAINT chronicle_events_chat_session_id_fkey 
FOREIGN KEY (chat_session_id) REFERENCES chat_sessions(id);
