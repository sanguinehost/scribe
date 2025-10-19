-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.499345
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- This file should undo anything in `up.sql`

-- Remove model_name column from chat_sessions table
ALTER TABLE chat_sessions
DROP COLUMN model_name;
