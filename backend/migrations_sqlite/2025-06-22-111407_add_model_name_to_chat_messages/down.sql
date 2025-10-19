-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:00:19.551561
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove model_name column from chat_messages table
ALTER TABLE chat_messages DROP COLUMN model_name;
