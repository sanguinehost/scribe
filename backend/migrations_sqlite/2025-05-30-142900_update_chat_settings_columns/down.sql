-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.500783
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

ALTER TABLE chat_sessions
ADD COLUMN repetition_penalty NUMERIC,
ADD COLUMN min_p NUMERIC,
ADD COLUMN top_a NUMERIC,
ADD COLUMN logit_bias TEXT;

ALTER TABLE chat_sessions
DROP COLUMN IF EXISTS stop_sequences;
