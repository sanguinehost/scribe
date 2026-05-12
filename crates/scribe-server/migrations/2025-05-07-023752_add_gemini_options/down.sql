-- This file should undo anything in `up.sql`

-- Remove Gemini-specific fields from chat_sessions
ALTER TABLE chat_sessions
DROP COLUMN gemini_thinking_budget,
DROP COLUMN gemini_enable_code_execution;
