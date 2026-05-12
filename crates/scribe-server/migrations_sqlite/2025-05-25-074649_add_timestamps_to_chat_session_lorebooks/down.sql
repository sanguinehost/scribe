-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.495809
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- This file should undo anything in `up.sql`
ALTER TABLE chat_session_lorebooks
DROP COLUMN created_at,
DROP COLUMN updated_at;
