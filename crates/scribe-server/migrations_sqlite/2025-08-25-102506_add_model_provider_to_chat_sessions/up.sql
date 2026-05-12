-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.507293
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add model_provider column to chat_sessions table (nullable initially)
ALTER TABLE chat_sessions ADD COLUMN model_provider TEXT;

-- Set default provider to 'gemini' for all existing records
-- Users can re-select local models if needed
UPDATE chat_sessions SET model_provider = 'gemini' WHERE model_provider IS NULL;
