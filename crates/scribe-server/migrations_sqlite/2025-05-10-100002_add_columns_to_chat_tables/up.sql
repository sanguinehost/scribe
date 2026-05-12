-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.500193
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add columns to chat_sessions and chat_messages
-- NOTE: These columns were already added in migration 2025-05-10-100000_add_frontend_tables
-- Making this a no-op to avoid duplicate column errors

-- ALTER TABLE chat_sessions ADD COLUMN visibility TEXT DEFAULT 'private';  -- Already added
-- ALTER TABLE chat_messages ADD COLUMN role TEXT;  -- Already added
-- ALTER TABLE chat_messages ADD COLUMN parts TEXT;  -- Already added
-- ALTER TABLE chat_messages ADD COLUMN attachments TEXT;  -- Already added
