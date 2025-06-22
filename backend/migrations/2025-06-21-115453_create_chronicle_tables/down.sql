-- Reverse the Chronicle tables migration
-- WARNING: This will permanently delete all Chronicle data

-- Drop indexes first
DROP INDEX IF EXISTS idx_chronicle_events_event_data_gin;
DROP INDEX IF EXISTS idx_chat_sessions_player_chronicle_id;
DROP INDEX IF EXISTS idx_chronicle_events_created_at;
DROP INDEX IF EXISTS idx_chronicle_events_source;
DROP INDEX IF EXISTS idx_chronicle_events_event_type;
DROP INDEX IF EXISTS idx_chronicle_events_user_id;
DROP INDEX IF EXISTS idx_chronicle_events_chronicle_id;
DROP INDEX IF EXISTS idx_player_chronicles_user_id;

-- Remove player_chronicle_id column from chat_sessions
ALTER TABLE chat_sessions 
DROP COLUMN player_chronicle_id;

-- Drop tables (order matters due to foreign keys)
DROP TABLE IF EXISTS chronicle_events;
DROP TABLE IF EXISTS player_chronicles;
