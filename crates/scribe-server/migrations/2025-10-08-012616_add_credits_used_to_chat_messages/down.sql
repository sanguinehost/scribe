-- Remove both credits columns and indexes
DROP INDEX IF EXISTS idx_chat_messages_session_charged;
DROP INDEX IF EXISTS idx_chat_messages_session_cost;

ALTER TABLE chat_messages
DROP COLUMN credits_charged,
DROP COLUMN credits_cost;
