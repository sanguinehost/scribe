-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:00:19.550739
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Reverse the changes from up.sql
-- NOTE: Making character_id NOT NULL again may fail if there are sessions without character_id
-- This should be handled carefully in production

-- Remove chat_mode column
ALTER TABLE chat_sessions
DROP COLUMN chat_mode;

-- Make character_id NOT NULL again (may fail if null values exist)
ALTER TABLE chat_sessions
ALTER COLUMN character_id SET NOT NULL;
