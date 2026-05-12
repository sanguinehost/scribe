-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.499487
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- This file should undo anything in `up.sql`

-- Remove Gemini-specific fields from chat_sessions
ALTER TABLE chat_sessions
DROP COLUMN gemini_thinking_budget,
DROP COLUMN gemini_enable_code_execution;
