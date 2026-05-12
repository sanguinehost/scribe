-- Revert proper cost tracking fields migration

-- Remove chat_sessions columns
DROP INDEX IF EXISTS idx_chat_messages_actual_cost;
DROP INDEX IF EXISTS idx_chat_messages_credit_cost;

ALTER TABLE chat_sessions
DROP COLUMN total_actual_charge;

ALTER TABLE chat_sessions
DROP COLUMN total_credit_cost;

ALTER TABLE chat_sessions
DROP COLUMN total_modified_cost;

ALTER TABLE chat_sessions
DROP COLUMN total_actual_cost;

-- Remove chat_messages columns
ALTER TABLE chat_messages
DROP COLUMN actual_charge;

ALTER TABLE chat_messages
DROP COLUMN credit_cost;

ALTER TABLE chat_messages
DROP COLUMN modified_cost;

ALTER TABLE chat_messages
DROP COLUMN actual_cost;
