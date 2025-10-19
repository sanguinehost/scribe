-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.500193
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add columns to chat_sessions if they don't exist
ALTER TABLE IF EXISTS chat_sessions ADD COLUMN IF NOT EXISTS visibility TEXT DEFAULT 'private';

-- Add columns to chat_messages if they don't exist
ALTER TABLE IF EXISTS chat_messages ADD COLUMN IF NOT EXISTS role TEXT;
ALTER TABLE IF EXISTS chat_messages ADD COLUMN IF NOT EXISTS parts TEXT;
ALTER TABLE IF EXISTS chat_messages ADD COLUMN IF NOT EXISTS attachments TEXT;
