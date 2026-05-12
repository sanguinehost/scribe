-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.507389
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove model_provider column from chat_sessions table
ALTER TABLE chat_sessions DROP COLUMN model_provider;
