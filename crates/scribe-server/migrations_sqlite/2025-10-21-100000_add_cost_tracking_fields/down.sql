-- Rollback: Remove cost tracking fields

-- Drop indexes
DROP INDEX IF EXISTS idx_chat_messages_credit_cost;
DROP INDEX IF EXISTS idx_chat_messages_actual_cost;

-- Remove fields from chat_sessions
-- Note: SQLite doesn't support DROP COLUMN, so we'd need to recreate the table
-- For now, this is a placeholder. In production, implement table recreation strategy.
-- ALTER TABLE chat_sessions DROP COLUMN total_actual_charge;
-- ALTER TABLE chat_sessions DROP COLUMN total_credit_cost;
-- ALTER TABLE chat_sessions DROP COLUMN total_modified_cost;
-- ALTER TABLE chat_sessions DROP COLUMN total_actual_cost;

-- Remove fields from chat_messages
-- ALTER TABLE chat_messages DROP COLUMN actual_charge;
-- ALTER TABLE chat_messages DROP COLUMN credit_cost;
-- ALTER TABLE chat_messages DROP COLUMN modified_cost;
-- ALTER TABLE chat_messages DROP COLUMN actual_cost;

-- SQLite limitation: Cannot drop columns in SQLite < 3.35.0
-- For down migration, would need to recreate tables without these columns
SELECT 'SQLite does not support DROP COLUMN. Manual migration required.' AS warning;
