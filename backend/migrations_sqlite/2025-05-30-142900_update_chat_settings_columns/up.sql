-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.500644
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Note: These columns already exist from previous migrations (2025-04-23-233746)
-- No need to add them again
-- ALTER TABLE chat_sessions ADD COLUMN repetition_penalty NUMERIC NULL;
-- ALTER TABLE chat_sessions ADD COLUMN min_p NUMERIC NULL;
-- ALTER TABLE chat_sessions ADD COLUMN top_a NUMERIC NULL;
-- ALTER TABLE chat_sessions ADD COLUMN logit_bias TEXT NULL;

-- Add stop_sequences column (TEXT array stored as TEXT in SQLite)
ALTER TABLE chat_sessions ADD COLUMN stop_sequences TEXT NULL;
