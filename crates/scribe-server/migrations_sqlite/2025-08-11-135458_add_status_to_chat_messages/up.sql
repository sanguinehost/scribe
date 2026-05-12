-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.504980
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add status tracking fields to chat_messages table
ALTER TABLE chat_messages ADD COLUMN status TEXT NOT NULL DEFAULT 'completed';
ALTER TABLE chat_messages ADD COLUMN error_message TEXT;
ALTER TABLE chat_messages ADD COLUMN superseded_at DATETIME;
-- Add index for efficient querying of active messages
CREATE INDEX idx_chat_messages_status ON chat_messages(session_id, status) WHERE superseded_at IS NULL;
