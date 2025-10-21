-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.499414
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here

-- Add Gemini-specific fields to chat_sessions
ALTER TABLE chat_sessions ADD COLUMN gemini_thinking_budget INTEGER;
ALTER TABLE chat_sessions ADD COLUMN gemini_enable_code_execution BOOLEAN;
