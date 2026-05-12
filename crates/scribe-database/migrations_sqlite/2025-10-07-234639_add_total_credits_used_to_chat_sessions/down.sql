-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.506943
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove total_credits_used column
ALTER TABLE chat_sessions
DROP COLUMN total_credits_used;
