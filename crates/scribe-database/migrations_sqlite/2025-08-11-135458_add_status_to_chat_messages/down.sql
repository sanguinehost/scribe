-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.505089
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop index
DROP INDEX IF EXISTS idx_chat_messages_status;

-- Remove status tracking fields from chat_messages table
ALTER TABLE chat_messages
DROP COLUMN IF EXISTS status,
DROP COLUMN IF EXISTS error_message,
DROP COLUMN IF EXISTS superseded_at;
