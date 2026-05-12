-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.499195
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- This file should undo anything in `up.sql`
ALTER TABLE chat_sessions
DROP COLUMN history_management_strategy,
DROP COLUMN history_management_limit;
